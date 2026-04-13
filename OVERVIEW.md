# certUpdate — Application Overview

## Purpose

certUpdate automates the end-to-end renewal of the SSL/TLS certificate on a Cisco ISE node. It retrieves a trusted public certificate from Let's Encrypt (using Azure DNS to prove domain ownership), then pushes it directly to ISE via the ISE REST API. The goal is to eliminate manual cert renewals while keeping the administrator in the loop when renewals are not yet urgent.

---

## Process Flow

### Step 1 — Check the current certificate expiry

The script opens a raw TLS connection to ISE, pulls the DER-encoded certificate from the handshake, parses it, and reads the `notAfter` field to determine how many days remain.

- **`ssl` / `socket`** — establish a raw TLS connection to ISE without verifying the certificate (since ISE may still have an untrusted or self-signed cert at this point). `getpeercert(binary_form=True)` returns the raw DER bytes.
- **`cryptography`** — `x509.load_der_x509_certificate()` parses the DER bytes into a structured cert object so `not_valid_after_utc` can be read. The standard `ssl.getpeercert()` is not used here because it returns an empty dict when certificate verification is disabled.
- **`datetime`** — calculates the difference between the expiry date and today to produce the days-remaining value.

---

### Step 2 — Decide whether to proceed

If fewer than 15 days remain, renewal is automatic. If more time remains, the user is prompted to confirm before continuing. The prompt self-cancels after 30 seconds if there is no response.

- **`select`** — `select.select()` is used to implement the timed prompt. It monitors `sys.stdin` with a timeout, so the script can wait for user input without blocking indefinitely. If the timeout expires before the user types, the select call returns an empty list and the script exits cleanly.

---

### Step 3 — Request a new certificate from Let's Encrypt

certbot is invoked as a subprocess using the `dns-azure` authenticator. The authenticator temporarily creates a DNS TXT record at `_acme-challenge.<domain>` in Azure DNS to prove domain ownership to Let's Encrypt. Once the challenge is validated, Let's Encrypt issues a signed certificate and the DNS record is deleted.

- **`subprocess.Popen`** — runs certbot and streams its stdout/stderr line by line in real time. `Popen` is used instead of `subprocess.run` so that DNS-related output (record creation, propagation wait, cleanup) is visible as it happens rather than being buffered until the process exits.
- **`configparser`** — all certbot parameters (credentials file, config/work/log directories, email, domain) are read from `config.ini` rather than hardcoded, keeping credentials out of source code.
- **`dig`** (external tool) — after certbot exits, a `dig +short TXT` query is run against the challenge record to confirm it has been removed from Azure DNS.

---

### Step 4 — Import the certificate to ISE

The renewed certificate and private key are read from disk, reformatted to match ISE's API requirements, and submitted via a single POST request to the ISE system certificate import endpoint. The API call simultaneously imports the certificate and binds it to all configured ISE services (admin portal, guest portals, EAP/802.1X, RADSec/DTLS).

- **`pathlib.Path`** — resolves the paths to the `fullchain.pem` and `privkey.pem` files written by certbot, and reads their contents.
- **`requests`** — sends the POST request to `https://<ise-host>/api/v1/certs/system-certificate/import` using HTTP Basic Auth and a JSON payload. `verify=False` is set because ISE may still present its old certificate during the import call.
- **`urllib3`** — `disable_warnings()` suppresses the `InsecureRequestWarning` that `requests` would otherwise print every time `verify=False` is used.
- **PEM formatting** — ISE's API requires the PEM file content as a single string with literal `\n` character sequences (two characters: backslash + n) between each line, rather than actual newline characters. The `format_pem()` function handles this conversion using `str.splitlines()` and `str.join()`.

---

### Step 5 — Verify the new certificate

The script re-runs Step 1 — opening a fresh TLS connection to ISE and reading the certificate — to confirm that the newly imported certificate is now being served and that its expiry date is in the future.

- Same **`ssl`**, **`socket`**, **`cryptography`**, and **`datetime`** usage as Step 1.
- If the days-remaining value is still below the threshold after the import, a warning is printed prompting the administrator to verify manually.

---

## Library Summary

| Library | Role |
|---------|------|
| `ssl` / `socket` | Open a raw TLS connection to ISE and retrieve the certificate bytes |
| `cryptography` | Parse DER-encoded certificate to extract the expiry date |
| `datetime` | Compute days remaining until certificate expiry |
| `select` | Implement a stdin prompt with a hard timeout |
| `subprocess.Popen` | Run certbot and stream its output line by line in real time |
| `configparser` | Load ISE credentials and certbot settings from `config.ini` |
| `pathlib` | Resolve and read certificate and private key file paths |
| `requests` | POST the certificate to the ISE REST API |
| `urllib3` | Suppress SSL verification warnings from `requests` |
| `sys` | Exit with appropriate return codes on error or user cancellation |
