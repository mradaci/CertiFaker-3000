#!/usr/bin/env python3
"""Enterprise CSR Generation Tool"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import platform
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path


# When packaged with PyInstaller --onefile, __file__ points to a temp extraction
# directory. sys.executable gives the actual .exe location in both cases.
SCRIPT_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
LOG_FILE = SCRIPT_DIR / "cert_gen.log"
LOG_SEP = "=" * 80
LOG_INNER_SEP = "-" * 80


# ── Audit logging ──────────────────────────────────────────────────────────────

def _get_file_logger() -> logging.Logger:
    logger = logging.getLogger("cert_gen.audit")
    if not logger.handlers:
        handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def audit_log(fields: dict[str, str], dry_run: bool = False) -> None:
    log = _get_file_logger()
    prefix = "[DRY-RUN] " if dry_run else ""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = os.environ.get("USERNAME") or os.environ.get("USER", "unknown")
    host = platform.node()

    lines = [
        "",
        LOG_SEP,
        f"{prefix}CERT GENERATION EVENT",
        f"Timestamp : {ts}",
        f"User      : {user}",
        f"Host      : {host}",
        LOG_INNER_SEP,
    ]
    for k, v in fields.items():
        lines.append(f"{k:<12}: {v}")
    lines.append(LOG_SEP)

    for line in lines:
        log.info(line)


# ── openssl helpers ────────────────────────────────────────────────────────────

def check_openssl() -> None:
    if shutil.which("openssl") is None:
        sys.exit("[ERROR] 'openssl' not found on PATH. Install or configure it before running.")
    # Some CNF files reference $ENV::HOME/.rnd; create it if absent to avoid OpenSSL 3 errors
    rnd = Path.home() / ".rnd"
    if not rnd.exists():
        rnd.touch()


def run_openssl(args: list[str], env: dict, capture: bool = False) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["openssl", *args],
        env=env,
        capture_output=capture,
        text=capture,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() if capture else "(see output above)"
        raise RuntimeError(f"openssl exited {result.returncode}: {detail}")
    return result


# ── CNF parsing ────────────────────────────────────────────────────────────────

CN_LINE_RE      = re.compile(r"^([ \t]*(?:CN|commonName)[ \t]*=[ \t]*)(.+?)[ \t]*$", re.MULTILINE | re.IGNORECASE)
CN_DEFAULT_RE   = re.compile(r"^[ \t]*(?:CN|commonName)_default[ \t]*=[ \t]*(.+?)[ \t]*$", re.MULTILINE | re.IGNORECASE)


def parse_cn(cnf_path: Path) -> str:
    """Read the CN from a cert directory's openssl.cnf.

    Two CNF styles are in circulation:

      prompt style  commonName         = Common Name (eg, your server's hostname)
                    commonName_default = host.example.com

      direct style  commonName         = host.example.com

    In prompt style the `commonName` value is the *label* openssl shows the
    operator, not the hostname — so when a `commonName_default` is present it
    wins. Otherwise the `commonName` value is the hostname itself.
    """
    content = cnf_path.read_text(encoding="utf-8", errors="replace")

    m = CN_DEFAULT_RE.search(content)
    if m:
        return m.group(1).strip()

    m = CN_LINE_RE.search(content)
    if m:
        return m.group(2).strip()

    raise ValueError(f"Could not locate commonName in {cnf_path}")


def effective_cnf(cnf_path: Path, cn: str) -> tuple[Path, Path | None]:
    """Return (config_to_use, temp_file_to_clean_up).

    `openssl req -batch` fills each DN field from that field's `_default` entry.
    A direct-style CNF has no `commonName_default`, so openssl treats the
    `commonName` line as a prompt label, finds no default, and silently drops CN
    from the subject — every other field still lands, which is why downstream
    intake forms show country/org/OU but a blank CN.

    When the CNF already carries a `commonName_default` it is used untouched.
    Otherwise a normalised copy is written to a temp file with the CN promoted
    into `commonName_default` so the batch run emits it.
    """
    content = cnf_path.read_text(encoding="utf-8", errors="replace")
    if CN_DEFAULT_RE.search(content):
        return cnf_path, None

    def _promote(match: re.Match) -> str:
        prefix = match.group(1)
        indent = prefix[:len(prefix) - len(prefix.lstrip())]
        field = prefix.strip().rstrip("=").strip()  # preserve CN vs commonName spelling
        return (
            f"{indent}{field} = Common Name (eg, your server's hostname)\n"
            f"{indent}{field}_default = {cn}"
        )

    patched, count = CN_LINE_RE.subn(_promote, content, count=1)
    if not count:
        raise ValueError(f"Could not locate commonName in {cnf_path}")

    fd, tmp_name = tempfile.mkstemp(prefix="opensslcnf_", suffix=".cnf", text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(patched)
    return Path(tmp_name), Path(tmp_name)


def csr_subject_cn(csr_text: str) -> str | None:
    """Pull the CN out of `openssl req -text` output, if present."""
    m = re.search(r"^\s*Subject:.*?\bCN\s*=\s*([^,/\n]+)", csr_text, re.MULTILINE)
    return m.group(1).strip() if m else None


# ── Path validation ────────────────────────────────────────────────────────────

def validate_path(path_str: str) -> tuple[Path, str | None]:
    """Return (path, error). error is None when valid."""
    p = Path(path_str).expanduser().resolve()
    if not p.is_dir():
        return p, f"Not a directory: {p}"
    cnf = p / "openssl.cnf"
    if not cnf.exists():
        return p, f"openssl.cnf not found in: {p}"
    try:
        parse_cn(cnf)
    except ValueError as exc:
        return p, str(exc)
    return p, None


# ── Prompts ────────────────────────────────────────────────────────────────────

def ask_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        resp = input(f"{prompt} [{hint}]: ").strip().lower()
        if not resp:
            return default
        if resp in ("y", "yes"):
            return True
        if resp in ("n", "no"):
            return False


def ask_key_size() -> int:
    while True:
        resp = input("  Key size [2048/4096] (default 2048): ").strip()
        if not resp:
            return 2048
        if resp in ("2048", "4096"):
            return int(resp)
        print("  Please enter 2048 or 4096.")


def ask_password(auto: bool | None = None) -> tuple[str, bool]:
    """Return (password, was_auto_generated)."""
    if auto is None:
        auto = ask_yes_no("  Auto-generate a secure password?", default=False)
    if auto:
        pwd = "".join(
            secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*")
            for _ in range(24)
        )
        print(f"\n  [AUTO-GENERATED PASSWORD]  {pwd}\n")
        return pwd, True
    while True:
        pwd = getpass.getpass("  Enter certificate password: ")
        confirm = getpass.getpass("  Confirm password: ")
        if pwd == confirm:
            return pwd, False
        print("  Passwords do not match. Try again.")


def collect_paths_interactive() -> list[str]:
    print("Enter cert directory paths (one per line). Press Enter on an empty line when done:\n")
    paths: list[str] = []
    while True:
        p = input(f"  Path {len(paths) + 1}: ").strip()
        if not p:
            if paths:
                break
            print("  At least one path is required.")
        else:
            paths.append(p)
    return paths


# ── Renewal archive ───────────────────────────────────────────────────────────

def archive_for_renewal(cert_path: Path, cn: str, dry_run: bool) -> Path | None:
    """Move all existing files (except openssl.cnf) into a timestamped backup folder."""
    files = sorted(f for f in cert_path.iterdir() if f.is_file() and f.name != "openssl.cnf")
    if not files:
        print("  [RENEWAL] No existing files to archive.")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = cert_path / f"{cn}_backup_{ts}"
    print(f"  [RENEWAL] Archiving {len(files)} file(s) → {backup_dir.name}/")
    for f in files:
        print(f"    • {f.name}")
    if not dry_run:
        backup_dir.mkdir()
        for f in files:
            shutil.move(str(f), backup_dir / f.name)
    return backup_dir


# ── Core cert processing ───────────────────────────────────────────────────────

def process_cert(
    cert_path: Path,
    shared_key_size: int | None,
    shared_password: str | None,
    shared_auto: bool | None,
    force: bool,
    dry_run: bool,
) -> None:
    cnf = cert_path / "openssl.cnf"
    cn = parse_cn(cnf)

    print(f"\n{'─' * 60}")
    print(f"  Directory : {cert_path}")
    print(f"  CN        : {cn}")
    print(f"{'─' * 60}")

    # New or Renewal
    while True:
        resp = input("  Certificate type — [N]ew / [R]enewal (default N): ").strip().upper()
        if resp in ("", "N"):
            cert_type = "NEW"
            break
        if resp == "R":
            cert_type = "RENEWAL"
            break

    # Per-cert settings when not shared
    key_size = shared_key_size or ask_key_size()
    if shared_password is not None:
        password, was_auto = shared_password, bool(shared_auto)
    else:
        password, was_auto = ask_password(auto=shared_auto)

    # File paths
    key_file  = cert_path / f"{cn}.key"
    csr_file  = cert_path / f"{cn}.csr"
    root_file = cert_path / f"{cn}-root.crt"
    inter_file = cert_path / f"{cn}-intermediate.crt"
    cert_file = cert_path / f"{cn}.crt"
    pass_file = cert_path / f"{cn}.password.txt"

    output_files = [key_file, csr_file, root_file, inter_file, cert_file]

    # Renewal: move all existing files into a timestamped archive folder
    backup_dir: Path | None = None
    if cert_type == "RENEWAL":
        backup_dir = archive_for_renewal(cert_path, cn, dry_run)
    else:
        # New cert: warn if output files already exist. A dry run only reports
        # them — there is nothing to overwrite, so it must not prompt or skip.
        existing = [f for f in output_files if f.exists()]
        if existing and not force:
            print(f"\n  [WARNING] These files already exist:")
            for f in existing:
                print(f"    • {f.name}")
            if dry_run:
                print("  [DRY-RUN] A real run would prompt before overwriting these.")
            elif not ask_yes_no("  Overwrite?", default=False):
                print("  Skipping.")
                return

    if dry_run:
        print(f"\n  [DRY-RUN] Would create:")
        print(f"    {key_file.name}  ({key_size}-bit RSA, AES-256 encrypted)")
        print(f"    {csr_file.name}")
        for f in [root_file, inter_file, cert_file]:
            print(f"    {f.name}  (empty placeholder)")
        if was_auto:
            print(f"    {pass_file.name}  (auto-generated password)")
        audit_log({
            "Path"    : str(cert_path),
            "CN"      : cn,
            "Type"    : cert_type,
            "Key Size": str(key_size),
            "Backup"  : str(backup_dir) if backup_dir else "N/A",
            "Status"  : "DRY-RUN — no files written",
        }, dry_run=True)
        return

    # Password is passed via environment variable — never exposed in process args
    env = {**os.environ, "OPENSSL_PASS": password}

    # Generate private key
    print(f"\n  Generating {key_size}-bit RSA private key...")
    run_openssl(
        ["genrsa", "-aes256", "-passout", "env:OPENSSL_PASS",
         "-out", str(key_file), str(key_size)],
        env=env,
    )

    # Generate CSR. A CNF without commonName_default would otherwise produce a
    # CSR with an empty CN, so normalise it first.
    print("  Generating CSR...")
    config, tmp_config = effective_cnf(cnf, cn)
    try:
        run_openssl(
            ["req", "-new", "-batch",
             "-key", str(key_file), "-passin", "env:OPENSSL_PASS",
             "-out", str(csr_file), "-config", str(config)],
            env=env,
        )
    finally:
        if tmp_config:
            tmp_config.unlink(missing_ok=True)

    # Verify CSR and display Subject + SANs for engineer confirmation
    print("\n  [CSR Verification]")
    result = run_openssl(
        ["req", "-text", "-noout", "-in", str(csr_file)],
        env=env,
        capture=True,
    )
    csr_dump = result.stdout + result.stderr
    for line in csr_dump.splitlines():
        stripped = line.strip()
        if any(kw in stripped for kw in ("Subject:", "DNS:", "IP Address:", "Subject Alternative")):
            print(f"    {stripped}")

    # Fail loudly rather than handing the cert team a CSR with a blank CN
    csr_cn = csr_subject_cn(csr_dump)
    if csr_cn is None:
        raise RuntimeError(
            f"CSR subject has no CN — {cnf} did not yield a common name. "
            "Check the commonName entry in that file."
        )
    if csr_cn != cn:
        raise RuntimeError(f"CSR CN '{csr_cn}' does not match the CN from {cnf} ('{cn}').")

    # Save auto-generated password to file
    if was_auto:
        pass_file.write_text(password, encoding="utf-8")
        print(f"\n  Password saved → {pass_file.name}")

    # Create empty placeholders
    print()
    for f in [root_file, inter_file, cert_file]:
        f.touch()
        print(f"  Placeholder  → {f.name}")

    # Write to central audit log
    audit_log({
        "Path"    : str(cert_path),
        "CN"      : cn,
        "Type"    : cert_type,
        "Key Size": str(key_size),
        "Password": password if was_auto else "USER-PROVIDED",
        "Backup"  : backup_dir.name if backup_dir else "N/A",
        "Files"   : ", ".join(f.name for f in output_files),
    })

    # Print CSR block formatted for ServiceNow paste
    csr_text = csr_file.read_text(encoding="utf-8")
    print(f"\n{'=' * 60}")
    print(f"  SERVICENOW SUBMISSION — {cn}")
    print(f"  Copy the CSR block below into the request form:")
    print(f"{'=' * 60}")
    print(csr_text)
    print("=" * 60)


# ── PFX export ─────────────────────────────────────────────────────────────────

# .crt is what the script writes now; .txt is still accepted so certs issued
# before the rename can be exported without renaming anything by hand.
CERT_SUFFIXES = (".crt", ".txt")
PEM_CERT_MARKER = "-----BEGIN CERTIFICATE-----"


def find_cert_file(cert_path: Path, stem: str) -> Path | None:
    """First populated cert file matching stem, preferring .crt over .txt."""
    for suffix in CERT_SUFFIXES:
        f = cert_path / f"{stem}{suffix}"
        if f.exists() and f.stat().st_size > 0:
            return f
    return None


def read_pem_certs(path: Path) -> str:
    """Read a PEM file, erroring if it holds no certificate block."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if PEM_CERT_MARKER not in text:
        raise RuntimeError(
            f"{path.name} contains no '{PEM_CERT_MARKER}' block. "
            "Paste the PEM text from the ServiceNow response into it."
        )
    return text if text.endswith("\n") else text + "\n"


def key_password_for(cert_path: Path, cn: str) -> str:
    """Password protecting {cn}.key — from the saved file, else prompted."""
    pass_file = cert_path / f"{cn}.password.txt"
    if pass_file.exists() and pass_file.stat().st_size > 0:
        print(f"  Password read from {pass_file.name}")
        return pass_file.read_text(encoding="utf-8").strip()
    return getpass.getpass(f"  Enter the password for {cn}.key: ")


def assert_key_matches_cert(key_file: Path, cert_file: Path, env: dict) -> None:
    """Refuse to build a PFX whose key and certificate are not a pair."""
    key_mod = run_openssl(
        ["rsa", "-noout", "-modulus", "-in", str(key_file), "-passin", "env:OPENSSL_PASS"],
        env=env, capture=True,
    ).stdout.strip()
    cert_mod = run_openssl(
        ["x509", "-noout", "-modulus", "-in", str(cert_file)],
        env=env, capture=True,
    ).stdout.strip()
    if key_mod != cert_mod:
        raise RuntimeError(
            f"{cert_file.name} was not issued for {key_file.name} — their public keys differ. "
            "Check that the pasted certificate came back from the CSR in this directory."
        )


def run_pkcs12_export(args: list[str], env: dict) -> bool:
    """Run `pkcs12 -export`, retrying without -legacy where it is unsupported.

    -legacy exists only in OpenSSL 3.x. On 1.x the flag is rejected outright,
    and the legacy algorithms it selects are already the default there, so
    dropping it on that path produces the same PFX.
    """
    try:
        run_openssl(["pkcs12", "-export", "-legacy", *args], env=env, capture=True)
        return True
    except RuntimeError as exc:
        if "legacy" not in str(exc).lower():
            raise
        print("  [NOTE] This OpenSSL build rejects -legacy; exporting without it.")
        run_openssl(["pkcs12", "-export", *args], env=env, capture=True)
        return False


def export_pfx(cert_path: Path, force: bool, dry_run: bool) -> None:
    cnf = cert_path / "openssl.cnf"
    cn = parse_cn(cnf)

    print(f"\n{'─' * 60}")
    print(f"  Directory : {cert_path}")
    print(f"  CN        : {cn}")
    print(f"{'─' * 60}")

    key_file = cert_path / f"{cn}.key"
    pfx_file = cert_path / f"{cn}.pfx"

    if not key_file.exists():
        raise RuntimeError(f"Private key not found: {key_file.name}")

    leaf_file = find_cert_file(cert_path, cn)
    if leaf_file is None:
        raise RuntimeError(
            f"Signed certificate {cn}.crt is missing or still empty. "
            "Paste the certificate from the ServiceNow response before exporting."
        )

    # The PFX carries the leaf certificate only. The -root and -intermediate
    # files are still generated and populated, but are deliberately not bundled.
    print(f"  Certificate : {leaf_file.name}")

    if pfx_file.exists() and not force:
        print(f"\n  [WARNING] {pfx_file.name} already exists.")
        if dry_run:
            print("  [DRY-RUN] A real run would prompt before overwriting it.")
        elif not ask_yes_no("  Overwrite?", default=False):
            print("  Skipping.")
            return

    if dry_run:
        print(f"\n  [DRY-RUN] Would create:")
        print(f"    {pfx_file.name}  (key + {leaf_file.name})")
        audit_log({
            "Path"    : str(cert_path),
            "CN"      : cn,
            "Type"    : "PFX EXPORT",
            "Cert"    : leaf_file.name,
            "Status"  : "DRY-RUN — no files written",
        }, dry_run=True)
        return

    # Validate every PEM input before touching openssl, so a half-pasted file
    # produces a clear message rather than an opaque openssl error.
    read_pem_certs(leaf_file)

    password = key_password_for(cert_path, cn)
    # Key password doubles as the PFX export password; both travel by env var.
    env = {**os.environ, "OPENSSL_PASS": password}

    print("\n  Verifying key and certificate match...")
    assert_key_matches_cert(key_file, leaf_file, env)
    print("    OK — certificate matches the private key.")

    args = [
        "-out", str(pfx_file),
        "-inkey", str(key_file),
        "-in", str(leaf_file),
        "-passin", "env:OPENSSL_PASS",
        "-passout", "env:OPENSSL_PASS",
    ]

    print("  Exporting PFX...")
    used_legacy = run_pkcs12_export(args, env=env)

    # Read the PFX back so a corrupt or empty export cannot pass silently
    verify = run_openssl(
        ["pkcs12", "-info", "-in", str(pfx_file), "-passin", "env:OPENSSL_PASS", "-nokeys"]
        + (["-legacy"] if used_legacy else []),
        env=env, capture=True,
    )
    subjects = [
        l.strip() for l in (verify.stdout + verify.stderr).splitlines()
        if l.strip().startswith("subject=")
    ]
    print(f"\n  [PFX Verification]  {pfx_file.name}")
    for subj in subjects:
        print(f"    {subj}")
    if not subjects:
        raise RuntimeError(f"{pfx_file.name} was written but contains no certificates.")

    audit_log({
        "Path"    : str(cert_path),
        "CN"      : cn,
        "Type"    : "PFX EXPORT",
        "Cert"    : leaf_file.name,
        "Certs"   : str(len(subjects)),
        "Files"   : pfx_file.name,
    })

    print(f"\n{'=' * 60}")
    print(f"  PFX READY — {pfx_file.name}")
    print(f"  Import password: same as the certificate password")
    print(f"{'=' * 60}")


# ── Input file parsing ─────────────────────────────────────────────────────────

def read_input_file(input_path: str) -> list[str]:
    p = Path(input_path).expanduser().resolve()
    if not p.exists():
        sys.exit(f"[ERROR] Input file not found: {p}")
    lines = p.read_text(encoding="utf-8").splitlines()
    paths = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    if not paths:
        sys.exit(f"[ERROR] No paths found in input file: {p}")
    print(f"  Loaded {len(paths)} path(s) from {p.name}")
    return paths


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enterprise CSR Generation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python gen_cert.py\n"
            "  python gen_cert.py --paths /certs/app1 /certs/app2 --keysize 4096 --autopass\n"
            "  python gen_cert.py --input batch.txt --keysize 4096 --autopass\n"
            "  python gen_cert.py --paths /certs/app1 --dry-run\n"
            "  python gen_cert.py --paths /certs/app1 --pfx\n"
        ),
    )
    parser.add_argument("--paths", nargs="+", metavar="DIR",
                        help="One or more cert directory paths (each must contain openssl.cnf)")
    parser.add_argument("--input", metavar="FILE",
                        help="Text file listing cert directory paths, one per line (# comments supported)")
    parser.add_argument("--keysize", type=int, choices=[2048, 4096],
                        help="RSA key size to apply to all certs")
    parser.add_argument("--autopass", action="store_true",
                        help="Auto-generate a unique secure password for each cert")
    parser.add_argument("--pfx", action="store_true",
                        help="Export {CN}.pfx from the populated cert files (run after pasting "
                             "the ServiceNow response); does not generate keys or CSRs")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing files without prompting")
    parser.add_argument("--dry-run", action="store_true", dest="dry_run",
                        help="Preview what would be created without writing any files")
    args = parser.parse_args()

    if args.paths and args.input:
        sys.exit("[ERROR] --paths and --input are mutually exclusive. Use one or the other.")

    # --pfx reads an existing key; it never generates one. Reject the
    # generation-only flags rather than ignoring them, so nothing reads as
    # having regenerated a key that was in fact left untouched.
    if args.pfx:
        conflicting = [
            flag for flag, given in (("--keysize", args.keysize), ("--autopass", args.autopass))
            if given
        ]
        if conflicting:
            verb = "does not" if len(conflicting) == 1 else "do not"
            noun = "the flag" if len(conflicting) == 1 else "those flags"
            sys.exit(
                f"[ERROR] {' and '.join(conflicting)} {verb} apply to --pfx — it exports an "
                f"existing key and certificate. Drop {noun}, or omit --pfx to generate a new key."
            )

    check_openssl()

    print("\n=== Enterprise Certificate Generation Tool ===")
    if args.pfx:
        print("    *** PFX EXPORT MODE — no keys or CSRs will be generated ***")
    if args.dry_run:
        print("    *** DRY-RUN MODE — no files will be written ***")
    print()

    if args.input:
        path_strings = read_input_file(args.input)
    elif args.paths:
        path_strings = args.paths
    else:
        path_strings = collect_paths_interactive()

    # ── Validate ALL paths before any cert work begins ──
    print("\n[Path Validation]")
    valid: list[Path] = []
    invalid_count = 0
    for ps in path_strings:
        p, err = validate_path(ps)
        if err:
            print(f"  [INVALID]  {err}")
            invalid_count += 1
        else:
            print(f"  [OK]       {p}")
            valid.append(p)

    if not valid:
        sys.exit("\nNo valid paths to process. Exiting.")

    if invalid_count and not ask_yes_no(
        f"\n{invalid_count} path(s) failed validation. "
        f"Continue with the {len(valid)} valid path(s)?"
    ):
        sys.exit(0)

    # ── PFX export mode: nothing below this applies ──
    if args.pfx:
        for cert_path in valid:
            try:
                export_pfx(
                    cert_path=cert_path,
                    force=args.force,
                    dry_run=args.dry_run,
                )
            except Exception as exc:
                print(f"\n  [ERROR] Failed exporting PFX for {cert_path}: {exc}")
                if not ask_yes_no("  Continue with remaining paths?"):
                    sys.exit(1)
        print("\n=== Complete ===\n")
        return

    # ── Shared settings for multi-cert batches ──
    shared_key_size: int | None = args.keysize
    shared_password: str | None = None
    shared_auto: bool | None = True if args.autopass else None

    if len(valid) > 1 and not args.keysize:
        if ask_yes_no("\nUse the same key size and password settings for all certs?"):
            shared_key_size = ask_key_size()
            shared_password, shared_auto = ask_password(auto=shared_auto)

    # ── Process each validated cert directory ──
    for cert_path in valid:
        try:
            process_cert(
                cert_path=cert_path,
                shared_key_size=shared_key_size,
                shared_password=shared_password,
                shared_auto=shared_auto,
                force=args.force,
                dry_run=args.dry_run,
            )
        except Exception as exc:
            print(f"\n  [ERROR] Failed processing {cert_path}: {exc}")
            if not ask_yes_no("  Continue with remaining paths?"):
                sys.exit(1)

    print("\n=== Complete ===\n")


if __name__ == "__main__":
    main()
