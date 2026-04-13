import ssl
import socket
import subprocess
import requests
import sys
import select
import datetime
import configparser
from pathlib import Path

# ---------------------------------------------------------------------------
# Load configuration from config.ini
# ---------------------------------------------------------------------------
CONFIG_FILE = Path(__file__).parent / "config.ini"
if not CONFIG_FILE.exists():
    print(f"ERROR: config.ini not found at {CONFIG_FILE}")
    sys.exit(1)

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

ISE_HOST       = config["ise"]["host"]
ISE_PORT       = int(config["ise"]["port"])
ISE_ADMIN_USER = config["ise"]["admin_user"]
ISE_ADMIN_PASS = config["ise"]["admin_pass"]

CERTBOT_EMAIL  = config["certbot"]["email"]
CERTBOT_DOMAIN = config["certbot"]["domain"]

# All paths are derived relative to the script's directory — no hardcoded paths
SCRIPT_DIR     = Path(__file__).parent
CERTBOT_CREDS  = SCRIPT_DIR / "certbot-azure.ini"
CERTBOT_CONFIG = SCRIPT_DIR / "config"
CERTBOT_WORK   = SCRIPT_DIR / "work"
CERTBOT_LOGS   = SCRIPT_DIR / "logs"

CERT_DIR  = CERTBOT_CONFIG / "live" / CERTBOT_DOMAIN
FULLCHAIN = CERT_DIR / "fullchain.pem"
PRIVKEY   = CERT_DIR / "privkey.pem"

EXPIRY_THRESHOLD = 15   # days — auto-renew if fewer than this many days remain
PROMPT_TIMEOUT   = 30   # seconds — quit if no response within this time

# Certificate roles to assign on ISE — set to True to enable each role
# Note: radius covers both RADSec and DTLS in the ISE API
CERT_ROLES = {
    "admin":  True,
    "portal": True,
    "eap":    True,
    "radius": True,
}


# ---------------------------------------------------------------------------
# Step 1 — Check current certificate expiry on ISE
# ---------------------------------------------------------------------------
def get_cert_expiry(host, port):
    print(f"Checking certificate on {host}:{port}...")
    try:
        from cryptography import x509 as crypto_x509
        from cryptography.hazmat.backends import default_backend
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
        cert = crypto_x509.load_der_x509_certificate(cert_bin, default_backend())
        expiry_date = cert.not_valid_after_utc.replace(tzinfo=None)
        days_remaining = (expiry_date - datetime.datetime.utcnow()).days
        return expiry_date, days_remaining
    except Exception as e:
        print(f"ERROR: Could not retrieve certificate from {host}:{port} — {e}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Step 2 — Prompt user with timeout if cert is not yet near expiry
# ---------------------------------------------------------------------------
def prompt_with_timeout(days_remaining, timeout):
    print(f"\nCertificate expires in {days_remaining} days (threshold: {EXPIRY_THRESHOLD} days).")
    print(f"Do you want to replace it anyway? (yes/no) — auto-quit in {timeout} seconds: ", end="", flush=True)

    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        response = sys.stdin.readline().strip().lower()
        return response in ("yes", "y")
    else:
        print("\nNo response received — quitting.")
        return False


# ---------------------------------------------------------------------------
# Step 3 — Request a new certificate from Let's Encrypt via certbot
# ---------------------------------------------------------------------------
def renew_certificate():
    if not CERTBOT_CREDS.exists():
        print(f"\nERROR: Azure credentials file not found: {CERTBOT_CREDS}")
        print("Create this file with your Azure service principal details.")
        print("See README.md for the required format.")
        sys.exit(1)

    print("\nRequesting new certificate from Let's Encrypt...")
    print(f"  Domain:          {CERTBOT_DOMAIN}")
    print(f"  DNS TXT record:  _acme-challenge.{CERTBOT_DOMAIN}")
    print(f"  Propagation wait: 30 seconds\n")
    cmd = [
        "certbot", "certonly",
        "--authenticator", "dns-azure",
        "--dns-azure-credentials", CERTBOT_CREDS,
        "--dns-azure-propagation-seconds", "30",
        "--config-dir", CERTBOT_CONFIG,
        "--work-dir", CERTBOT_WORK,
        "--logs-dir", CERTBOT_LOGS,
        "--agree-tos",
        "--email", CERTBOT_EMAIL,
        "--force-renewal",
        "--non-interactive",
        "-v",
        "-d", CERTBOT_DOMAIN,
    ]
    # Stream output line by line so DNS create/delete steps are visible in real time
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    dns_keywords = ["adding", "removing", "cleanup", "cleaning", "txt", "record",
                    "acme-challenge", "challenge", "waiting", "propagat", "verif",
                    "success", "error", "failed", "dns"]
    for line in process.stdout:
        line = line.rstrip()
        if any(kw in line.lower() for kw in dns_keywords):
            print(f"  {line}")
    process.wait()
    if process.returncode != 0:
        print(f"\nERROR: certbot failed — check {CERTBOT_LOGS}/letsencrypt.log for details")
        sys.exit(1)

    # Verify the DNS TXT record was cleaned up after validation
    txt_record = f"_acme-challenge.{CERTBOT_DOMAIN}"
    print(f"\n  Verifying DNS cleanup of {txt_record}...")
    dns_check = subprocess.run(
        ["dig", "+short", "TXT", txt_record],
        capture_output=True, text=True
    )
    if dns_check.stdout.strip():
        print(f"  WARNING: TXT record still present — may not have propagated yet: {dns_check.stdout.strip()}")
    else:
        print(f"  DNS TXT record {txt_record} successfully deleted.")

    print("\nCertificate successfully obtained from Let's Encrypt.")


# ---------------------------------------------------------------------------
# Step 4 — Apply the certificate to ISE via OpenAPI
# ---------------------------------------------------------------------------
def format_pem(path):
    # ISE requires PEM content with literal \n between each line (not actual newlines)
    # Matches the awk command: awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}'
    lines = path.read_text().splitlines()
    return "\\n".join(line for line in lines if line.strip())


def apply_certificate_to_ise():
    print("\nApplying certificate to ISE...")

    base_url = f"https://{ISE_HOST}"
    auth = (ISE_ADMIN_USER, ISE_ADMIN_PASS)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    # Read and format cert and key files
    try:
        cert_data = format_pem(FULLCHAIN)
        key_data = format_pem(PRIVKEY)
    except Exception as e:
        print(f"ERROR: Could not read certificate files — {e}")
        sys.exit(1)

    # Step 1: Import the cert with a date-stamped unique name and no roles yet.
    # Assigning roles at import time can silently fail if a cert with the same
    # name or subject already exists. Separating import from role assignment
    # avoids this and gives us a reliable cert ID to work with.
    cert_name = f"ise-sankey-io-{datetime.datetime.utcnow().strftime('%Y%m%d')}"
    print(f"  Importing certificate as '{cert_name}'...")
    import_payload = {
        "name":                              cert_name,
        "data":                              cert_data,
        "privateKeyData":                    key_data,
        "password":                          "",
        "admin":                             False,
        "eap":                               False,
        "radius":                            False,
        "portal":                            False,
        "portalGroupTag":                    "Default Portal Certificate Group",
        "pxgrid":                            False,
        "ims":                               False,
        "saml":                              False,
        "allowOutOfDateCert":                False,
        "allowSHA1Certificates":             False,
        "allowExtendedValidity":             True,
        "allowWildCardCertificates":         False,
        "allowRoleTransferForSameSubject":   True,
        "allowPortalTagTransferForSameSubject": True,
        "allowReplacementOfCertificates":    True,
        "allowReplacementOfPortalGroupTag":  True,
        "validateCertificateExtensions":     False,
    }

    response = requests.post(
        f"{base_url}/api/v1/certs/system-certificate/import",
        auth=auth, headers=headers, json=import_payload, verify=False
    )

    if response.status_code not in (200, 201):
        print(f"ERROR: Certificate import failed ({response.status_code}): {response.text}")
        sys.exit(1)

    cert_id = response.json().get("response", {}).get("id")
    if not cert_id:
        print(f"ERROR: Import succeeded but no cert ID returned. Response: {response.text}")
        sys.exit(1)
    print(f"  Certificate imported. ID: {cert_id}")

    # Step 2: Assign roles to the new cert via PUT using the cert ID.
    # This explicitly binds the new cert to all configured ISE services,
    # transferring roles away from whichever cert previously held them.
    print("  Assigning roles to new certificate...")
    put_payload = {
        "name":                              cert_name,
        "admin":                             CERT_ROLES["admin"],
        "eap":                               CERT_ROLES["eap"],
        "radius":                            CERT_ROLES["radius"],
        "portal":                            CERT_ROLES["portal"],
        "portalGroupTag":                    "Default Portal Certificate Group",
        "allowRoleTransferForSameSubject":   True,
        "allowPortalTagTransferForSameSubject": True,
        "allowReplacementOfCertificates":    True,
        "allowReplacementOfPortalGroupTag":  True,
    }

    put_response = requests.put(
        f"{base_url}/api/v1/certs/system-certificate/{ISE_HOST}/{cert_id}",
        auth=auth, headers=headers, json=put_payload, verify=False
    )

    if put_response.status_code not in (200, 201):
        print(f"ERROR: Role assignment failed ({put_response.status_code}): {put_response.text}")
        sys.exit(1)

    message = put_response.json().get("response", {}).get("message", "")
    print(f"  Roles assigned successfully.")
    if message:
        print(f"  ISE message: {message}")


# ---------------------------------------------------------------------------
# Step 5 — Wait for ISE to restart, then verify the new certificate is active
# ---------------------------------------------------------------------------
def wait_for_ise(timeout=300, interval=15):
    print(f"\nWaiting for ISE to restart (timeout: {timeout}s)...")
    deadline = datetime.datetime.utcnow() + datetime.timedelta(seconds=timeout)
    attempt = 0
    while datetime.datetime.utcnow() < deadline:
        attempt += 1
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ISE_HOST, ISE_PORT), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ISE_HOST):
                    pass
            print(f"  ISE is back online.")
            return True
        except Exception:
            elapsed = (datetime.datetime.utcnow() - (deadline - datetime.timedelta(seconds=timeout))).seconds
            print(f"  ISE not responding yet... ({elapsed}s elapsed, retrying in {interval}s)")
            import time
            time.sleep(interval)
    print(f"  WARNING: ISE did not come back within {timeout} seconds — verify manually.")
    return False


def verify_new_certificate():
    wait_for_ise()
    print("\nVerifying new certificate on ISE...")
    expiry_date, days_remaining = get_cert_expiry(ISE_HOST, ISE_PORT)
    print(f"New certificate expires: {expiry_date.strftime('%Y-%m-%d')} ({days_remaining} days remaining)")
    if days_remaining > EXPIRY_THRESHOLD:
        print("Certificate successfully applied and verified.")
    else:
        print("WARNING: New certificate expiry is unexpectedly low — verify manually.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("ISE Certificate Manager")
    print("=" * 60)

    # Check current cert expiry
    expiry_date, days_remaining = get_cert_expiry(ISE_HOST, ISE_PORT)
    print(f"Current certificate expires: {expiry_date.strftime('%Y-%m-%d')} ({days_remaining} days remaining)")

    # Decide whether to proceed
    if days_remaining <= EXPIRY_THRESHOLD:
        print(f"\nCertificate expires in {days_remaining} days — automatically renewing.")
        proceed = True
    else:
        proceed = prompt_with_timeout(days_remaining, PROMPT_TIMEOUT)

    if not proceed:
        print("Exiting without renewing certificate.")
        sys.exit(0)

    # Renew and apply
    renew_certificate()
    apply_certificate_to_ise()
    verify_new_certificate()

    print("\nDone.")


if __name__ == "__main__":
    # Suppress SSL warnings for ISE self-signed cert
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
