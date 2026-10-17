# CNS Security Lab

An educational Flask security lab for encrypted messaging, signature verification, an explicitly authorized manual relay, malware scanning, private file sharing, account security, and audit events. Use it only on an isolated VirtualBox host-only network.

## Three-machine topology

| Machine | Role | Example host-only IP |
|---|---|---|
| Windows | User portal, first account | `192.168.56.1` |
| Ubuntu | Flask/SQLite/key host and authorized attacker console | `192.168.56.102` |
| Kali | User portal, second account | `192.168.56.101` |

Ubuntu runs the app and owns the server-side keys. Windows and Kali are user clients. Open the attacker console locally on Ubuntu at `/attacker`; it is administrator-only. From Windows and Kali, use the user portal. Make sure all three VMs use the same host-only network and do not expose this development server to a bridged or public interface.

## Ubuntu setup

Install packages and ClamAV:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip openssl clamav clamav-freshclam
clamscan --version
```

Ubuntu's `clamav-freshclam` service normally owns database updates. Check it with `systemctl status clamav-freshclam` and
let it finish updating; do not run a second `sudo freshclam` while that service is active (both processes use the same
update log/database lock). If you need a one-time manual update, stop the service, run the updater, then start the service:
`sudo systemctl stop clamav-freshclam && sudo freshclam && sudo systemctl start clamav-freshclam`.

From the project directory, create/activate the existing virtual environment if needed, install requirements, generate a TLS certificate if you do not already have a trusted lab certificate, then initialize safely:

```bash
python3 -m venv .venv        # only if .venv does not already exist
source .venv/bin/activate
pip install -r requirements.txt
python3 scripts/generate_lab_tls.py --ip 192.168.56.102
python3 scripts/init_db.py
```

`init_db.py` creates `.env` only if absent, creates keys only for a new empty instance, and makes a dated backup when an existing DB/key store is present. It never regenerates a missing key for a populated DB. The app applies only its supported additive SQLite migrations after making a backup. Keep the existing `.env`, `instance/`, database, and keys when updating code; never replace them with a fresh copy.

For HTTPS, edit `.env` on Ubuntu and set at least:

```dotenv
REQUIRE_HTTPS=1
SESSION_COOKIE_SECURE=1
TLS_CERT_FILE=instance/tls/lab.crt
TLS_KEY_FILE=instance/tls/lab.key
APP_HOST=0.0.0.0
APP_PORT=5000
```

Keep the generated `lab.key` only on Ubuntu. Copy **only** `lab.crt` to Windows and Kali, then trust it as a root certificate on each client VM. Windows (elevated PowerShell): `certutil -addstore -f Root lab.crt`. Kali: `sudo install -m 0644 lab.crt /usr/local/share/ca-certificates/cns-lab.crt && sudo update-ca-certificates`. The generated certificate is self-signed for this isolated lab; clients must trust it before using browser cryptography. If a CA certificate already exists for the lab, use that instead of generating a replacement.

Start the server from the project directory:

```bash
source .venv/bin/activate
python3 app.py
```

The `.env` paths for the instance and TLS files are resolved from this project directory, even if a shell starts `app.py` from elsewhere. This prevents Flask from silently selecting a second `instance/` directory. The current checked-in runtime settings require HTTPS; startup will correctly stop if `instance/tls/lab.crt` or `instance/tls/lab.key` is missing. Do not initialize a replacement database or regenerate the message master key to work around that error. Restore the existing TLS pair from the Ubuntu host backup, or, for an isolated local HTTP development run only, explicitly clear the TLS paths and secure-cookie requirement for that process:

```bash
REQUIRE_HTTPS=0 SESSION_COOKIE_SECURE=0 TLS_CERT_FILE= TLS_KEY_FILE= python3 app.py
```

That development listener is plain HTTP and does not provide browser transport encryption; use a trusted HTTPS listener for protected browser submissions and shared lab use.

The default ClamAV scan timeout is 120 seconds to allow a cold scanner to load definitions on a small VM. Existing `.env`
files are preserved; add `CLAMSCAN_TIMEOUT=120` there and restart the app if scans still use the old 30-second setting.
The app refuses to start if HTTPS is required but the configured certificate or private key is missing. Use the same HTTPS origin from both clients:

- User portal: `https://192.168.56.102:5000/`
- Attacker console (Ubuntu admin only): `https://192.168.56.102:5000/attacker`
- Virus Detection: `https://192.168.56.102:5000/virus-scanner`
- File Sharing: `https://192.168.56.102:5000/files`
- Security Events: `https://192.168.56.102:5000/events`

Register the `admin` account first if the configured `ADMIN_USERNAMES` includes `admin`, then register separate user accounts for Windows and Kali. The first account is not automatically privileged unless its name is configured as an administrator.

## Tests and diagnostics

```bash
source .venv/bin/activate
python3 -m pytest
python3 scripts/health_check.py https://192.168.56.102:5000 --ca-cert instance/tls/lab.crt
```

## Three-VM operator quick reference

Use one URL scheme and hostname consistently in the browser. If Flask is serving HTTPS, use `https://192.168.56.102:5000` from Windows and Kali after trusting only the lab's public certificate. The admin operator uses `/attacker` on Ubuntu. If Flask is serving HTTP, use `http://192.168.56.102:5000` everywhere; browser transport encryption is unavailable over HTTP, but unprotected relay demonstrations still work. A TLS client sent to the HTTP listener produces binary-looking HTTP 400 log lines; that is a scheme/port mismatch, not a ClamAV or CSRF error.

Useful pages and endpoints:

- User portal and command dashboard: `/dashboard`
- Manual attacker relay (Ubuntu admin only): `/attacker`
- Live chart data (authenticated): `/api/dashboard/metrics`
- Component diagnostics (authenticated): `/api/diagnostics`
- Security notifications: `/notifications`
- Security events CSV report: `/events.csv`
- Virus Detection and scan report: `/virus-scanner` and `/virus-scanner/reports.csv`
- Private file sharing and SHA-256 verification: `/files`

The dashboard charts use stored security events, current signature checks over authorized messages, intercepted-message states, login-attempt records, scan records, and file-integrity events. Severity shows only the application's stored `info`, `warning`, and `critical` values. Notifications are per-account records derived from warning/critical events and selected account-security events. Only CSV reports are implemented; a PDF export is not configured.

The relay-specific CSRF bug was in `templates/attacker.html`: it is a standalone page and did not load the shared `static/js/app.js` helper. Its JavaScript called `window.cnsPostJSON`, which fetches a current Flask-WTF token and sends `X-CSRFToken`; without that script, attacker relay actions could not submit correctly. The page now loads the helper before `attacker.js`, and a regression test checks the script order. CSRF remains enabled. Separately, the supplied binary-looking HTTP 400 logs indicate that an HTTPS/TLS client reached an HTTP listener; use the same scheme on Flask and in all three VM browsers.

Static CSS and JavaScript URLs include a SHA-256 content version, so changed files get new URLs even when deploys preserve timestamps. Rendered pages are sent without caching. This project does not register a service worker. If an older browser profile still behaves differently, open the exact lab origin and clear that origin's site data, unregister any old CNS service worker if one appears under browser developer tools → Application → Service Workers, then hard reload. Use the same scheme, hostname, and port in normal and private windows; HTTP and HTTPS cookies belong to separate origins, and an old session cookie can refer to a different app/database copy.

For VirtualBox shared-folder deployments, source edits should remain under `/media/sf_cnsproject/cns-security-lab`, while SQLite, keys, uploads, and TLS private keys are safer on Ubuntu's local filesystem. Stop Flask before taking a backup or copying the instance. See [docs/three-vm-operations.md](docs/three-vm-operations.md) for a data-preserving move procedure; it copies the existing database and keys and never regenerates them.

Tests mock ClamAV where appropriate. Real scans require installed ClamAV and updated definitions. A missing or failed scanner never results in a `CLEAN` status. See [docs/testing.md](docs/testing.md), [docs/architecture.md](docs/architecture.md), [docs/limitations.md](docs/limitations.md), and [docs/transport-demo.md](docs/transport-demo.md).

## Capabilities and security boundaries

- Messages use AES-256-GCM and Ed25519; inbox and sent pages filter metadata server-side and paginate results. Invalid signatures never return plaintext.
- Plaintext lab submissions are held by Ubuntu's relay until an administrator explicitly forwards the unchanged original, forwards an edited copy, or drops it. Edited content retains the sender's original signature and fails recipient verification.
- Virus Detection stores scan metadata, not the uploaded scan bytes. File sharing accepts only files ClamAV scanned clean; shares are private, revocable, and downloads verify SHA-256.
- Account Security shows active/revoked sessions, allows session revocation, and changes passwords only after current-password verification.
- Security-event and scan CSV exports apply spreadsheet-formula escaping and the caller's authorization scope.

The service is an educational development server, not a production deployment. The server controls the message keys, so this is not end-to-end encryption. See the limitations document before presenting the lab.
