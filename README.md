# CertiFaker 3000

An enterprise-grade CLI tool for automating OpenSSL certificate signing request (CSR) generation against internal certificate authorities. Handles key generation, CSR creation, placeholder file scaffolding, renewal archiving, and batch processing — all driven by per-directory `openssl.cnf` files.

---

## Requirements

- Python 3.10+
- OpenSSL on system `PATH`
- No third-party Python packages — stdlib only

---

## Setup

Place `gen_cert.py` in a shared/central location. It does not need to live alongside the cert directories it operates on.

```
\\fileserver\tools\gen_cert.py
```

---

## How It Works

Each certificate lives in its own directory containing an `openssl.cnf`. The script reads the `commonName_default` field from that file to derive the CN, which drives all output file naming. No manual filename input is required.

**Output files generated per cert:**

| File | Description |
|---|---|
| `{CN}.key` | AES-256 encrypted RSA private key |
| `{CN}.csr` | Certificate signing request — submit to cert team |
| `{CN}-root.txt` | Empty placeholder for root certificate |
| `{CN}-intermediate.txt` | Empty placeholder for intermediate certificate |
| `{CN}.txt` | Empty placeholder for signed certificate |
| `{CN}.password.txt` | Auto-generated password (only if auto-gen chosen) |

---

## Usage

### Interactive (single or multiple certs)

```
python gen_cert.py
```

The script prompts for one or more cert directory paths, validates all of them upfront, then walks through each cert interactively.

---

### Batch via input file

```
python gen_cert.py --input batch.txt
```

`batch.txt` is a plain text file with one cert directory path per line. Blank lines and `#` comments are ignored.

```
# Q2 renewals - June 2026
\\fileserver\certs\AppServer01
\\fileserver\certs\WebGateway
\\fileserver\certs\PaymentsAPI
\\fileserver\certs\AuthService
```

---

### CLI flags (Blue Prism / automated use)

```
python gen_cert.py --paths "C:\certs\AppServer01" "C:\certs\WebGateway" --keysize 2048 --autopass --force
```

---

## All Flags

| Flag | Description |
|---|---|
| `--paths DIR [DIR ...]` | One or more cert directory paths |
| `--input FILE` | Batch input file (one path per line) |
| `--keysize {2048,4096}` | RSA key size — applies to all certs in the run (default: 2048) |
| `--autopass` | Auto-generate a unique secure password for each cert |
| `--force` | Overwrite existing files without prompting |
| `--dry-run` | Preview all actions without writing any files |

`--paths` and `--input` are mutually exclusive.

---

## Walkthrough

### 1. New certificate

```
python gen_cert.py --paths C:\certs\AppServer01
```

```
[Path Validation]
  [OK]  C:\certs\AppServer01

  Directory : C:\certs\AppServer01
  CN        : appserver01.corp.example.com

  Certificate type — [N]ew / [R]enewal (default N): N
  Key size [2048/4096] (default 2048):
  Auto-generate a secure password? [y/N]: y

  [AUTO-GENERATED PASSWORD]  xK9$mP2#vRqLnT8&

  Generating 2048-bit RSA private key...
  Generating CSR...

  [CSR Verification]
    Subject: C=US, ST=New York, O=Acme Corporation, CN=appserver01.corp.example.com
    X509v3 Subject Alternative Name:
    DNS:appserver01.internal.example.com

  Password saved → appserver01.corp.example.com.password.txt
  Placeholder    → appserver01.corp.example.com-root.txt
  Placeholder    → appserver01.corp.example.com-intermediate.txt
  Placeholder    → appserver01.corp.example.com.txt

  ============================================================
  SERVICENOW SUBMISSION — appserver01.corp.example.com
  Copy the CSR block below into the request form:
  ============================================================
  -----BEGIN CERTIFICATE REQUEST-----
  MIIFLjCCAxYCAQAwgZcxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhOZXcgWW9yazET
  ...
  -----END CERTIFICATE REQUEST-----
  ============================================================
```

---

### 2. Renewal

Selecting `R` at the cert type prompt archives every existing file in the directory (except `openssl.cnf`) into a timestamped subfolder before generating fresh files.

```
  Certificate type — [N]ew / [R]enewal (default N): R

  [RENEWAL] Archiving 6 file(s) → appserver01.corp.example.com_backup_20260606_120552/
    • appserver01.corp.example.com.key
    • appserver01.corp.example.com.csr
    • appserver01.corp.example.com-root.txt
    • appserver01.corp.example.com-intermediate.txt
    • appserver01.corp.example.com.txt
    • appserver01.corp.example.com.password.txt
```

Nothing is deleted. All prior files remain intact in the backup folder.

---

### 3. Dry run

Preview exactly what would be created or archived without touching any files:

```
python gen_cert.py --input batch.txt --keysize 4096 --autopass --dry-run
```

---

### 4. Batch run (multiple certs, shared settings)

```
python gen_cert.py --input batch.txt
```

When running multiple certs, the script offers to apply the same key size and password settings across all of them. Each cert still prompts individually for New or Renewal.

If any paths fail validation (missing directory, missing `openssl.cnf`, unreadable CN), the script reports them and asks whether to continue with the valid paths before any cert work begins.

---

## Audit Log

Every run appends a structured event block to `cert_gen.log`, stored in the same directory as `gen_cert.py`.

```
================================================================================
CERT GENERATION EVENT
Timestamp : 2026-06-06 12:05:52
User      : jsmith
Host      : WORKSTATION01
--------------------------------------------------------------------------------
Path        : \\fileserver\certs\AppServer01
CN          : appserver01.corp.example.com
Type        : RENEWAL
Key Size    : 2048
Password    : xK9$mP2#vRqLnT8&
Backup      : appserver01.corp.example.com_backup_20260606_120552
Files       : appserver01.corp.example.com.key, appserver01.corp.example.com.csr, ...
================================================================================
```

Each event is clearly separated. Dry-run entries are prefixed with `[DRY-RUN]`.

---

## Network Paths

The script works with mapped drives and UNC paths without any configuration changes:

```
# batch.txt
\\fileserver01\certs\AppServer01
Z:\certs\WebGateway
```

OpenSSL runs locally on the machine executing the script. Files are written to the network path. No OpenSSL dependency on the remote machine.

---

## PyInstaller Packaging

The script is stdlib-only and PyInstaller-ready. To build a standalone Windows executable:

```
pip install pyinstaller
pyinstaller --onefile gen_cert.py
```

The resulting `dist\gen_cert.exe` can be invoked by Blue Prism or any automation platform via CLI flags:

```
gen_cert.exe --input batch.txt --keysize 2048 --autopass --force
```

The audit log writes alongside the `.exe` in all deployment modes.

---

## openssl.cnf Requirements

Each cert directory must contain an `openssl.cnf` with at minimum:

```ini
[ req_distinguished_name ]
commonName_default = appserver01.corp.example.com

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = appserver01.corp.example.com
```

The `commonName_default` value drives all output file naming for that cert.
