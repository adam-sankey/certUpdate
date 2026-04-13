# certUpdate

Automates SSL/TLS certificate renewal for Cisco ISE using Let's Encrypt with Azure DNS validation.

## What it does

1. Connects to ISE and checks the current certificate's expiry date
2. If fewer than 15 days remain, automatically proceeds with renewal
3. If more than 15 days remain, prompts the user (30-second timeout) before proceeding
4. Requests a new certificate from Let's Encrypt using DNS-01 challenge via Azure DNS
5. Imports the new certificate to ISE via the ISE OpenAPI and binds it to all configured services
6. Verifies the new certificate is active by re-checking the expiry date

## Prerequisites

- Python 3.8+
- `certbot` installed and available in PATH
- `certbot-dns-azure` plugin installed
- `dig` available in PATH (for DNS cleanup verification)
- Azure service principal with DNS Zone Contributor permissions on the Azure DNS zone
- ISE 3.4+ with API access enabled

### Python dependencies

```bash
pip install requests cryptography
pip install certbot certbot-dns-azure "azure-mgmt-dns<9.0.0"
```

> **Note:** `azure-mgmt-dns<9.0.0` is required — version 9.0.0 is incompatible with certbot-dns-azure.

## Configuration

### config.ini

Create `config.ini` in the same directory as the script (excluded from git):

```ini
[ise]
host = ise.example.com
port = 443
admin_user = admin
admin_pass = yourpassword

[certbot]
credentials = /path/to/certbot-azure.ini
config_dir = /path/to/certUpdate/config
work_dir = /path/to/certUpdate/work
logs_dir = /path/to/certUpdate/logs
email = you@example.com
domain = ise.example.com
```

### certbot-azure.ini

Create `certbot-azure.ini` in the same directory (excluded from git):

```ini
dns_azure_sp_client_id = <azure-app-client-id>
dns_azure_sp_client_secret = <azure-app-client-secret>
dns_azure_tenant_id = <azure-tenant-id>
dns_azure_zone1 = example.com:/subscriptions/<subscription-id>/resourceGroups/<resource-group>
```

The Azure service principal needs the **DNS Zone Contributor** role on the DNS zone resource.

## ISE trusted certificates

Let's Encrypt uses the E8 intermediate CA, which chains to **ISRG Root X2** (not Root X1). Before running the script for the first time, import the trust chain into ISE:

1. **ISE Admin UI → Administration → System → Certificates → Trusted Certificates**
2. Import `lets-encrypt-e8.pem` (E8 intermediate CA)
3. Import `isrg-root-x2.pem` (ISRG Root X2)

Both PEM files are included in this repository.

## Usage

```bash
python3 certUpdate.py
```

The script runs non-interactively when the cert is near expiry. When run with plenty of time remaining, it prompts:

```
Certificate expires in 45 days (threshold: 15 days).
Do you want to replace it anyway? (yes/no) — auto-quit in 30 seconds:
```

Type `yes` to proceed or `no` (or wait 30 seconds) to exit without changes.

## Certificate roles

The script binds the imported certificate to the following ISE services, controlled by the `CERT_ROLES` dict at the top of the script:

| Role | Enabled | Description |
|------|---------|-------------|
| admin | Yes | Admin portal HTTPS |
| portal | Yes | Guest/sponsor portals |
| eap | Yes | 802.1X / EAP authentication |
| radius | Yes | RADSec and DTLS |

## Let's Encrypt rate limits

Let's Encrypt allows **5 duplicate certificates per week** for the same domain. Use the `--staging` flag in the certbot command during testing to avoid consuming this quota. Staging certificates are not trusted by ISE but the full DNS challenge flow still runs.

Check issued certificates at [crt.sh](https://crt.sh) by searching your domain name.

## Files

```
certUpdate/
├── certUpdate.py           # Main script
├── config.ini              # ISE and certbot settings (gitignored)
├── certbot-azure.ini       # Azure service principal credentials (gitignored)
├── lets-encrypt-e8.pem     # Let's Encrypt E8 intermediate CA
├── isrg-root-x2.pem        # ISRG Root X2 root CA
├── config/                 # certbot config and issued certs (gitignored)
├── work/                   # certbot working directory (gitignored)
└── logs/                   # certbot logs (gitignored)
```
