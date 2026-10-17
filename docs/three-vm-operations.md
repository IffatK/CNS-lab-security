# Three-VM runbook

## Roles and addresses

- Windows VM: user browser and first user account.
- Kali VM: user browser and second user account.
- Ubuntu VM: Flask server, SQLite database, cryptographic keys, ClamAV, authorized attacker operator.

The example host-only network uses Ubuntu `192.168.56.102`, Windows `192.168.56.1`, and Kali `192.168.56.101`. Confirm the actual addresses in VirtualBox before use. Keep the adapter on a private host-only network.

## Preserve data and move writable state off the shared folder

The shared source path on Ubuntu is `/media/sf_cnsproject/cns-security-lab`. If `CNS_INSTANCE_DIR` is not set, the app currently uses that working tree's `instance/` directory for `cns_lab.db`, `keys/`, `shared-files/`, and `scanner-tmp/`. SQLite locking and POSIX permission behavior can be unreliable on VirtualBox shared folders. Use Ubuntu-local storage for the live instance when possible.

Stop Flask with Ctrl+C before copying. From the project root:

```bash
cd /media/sf_cnsproject/cns-security-lab
source .venv/bin/activate
python3 scripts/backup_instance.py
export CNS_DATA_DIR="$HOME/.local/share/cns-security-lab"
mkdir -p "$CNS_DATA_DIR"
cp -a instance/. "$CNS_DATA_DIR/"
chmod 700 "$CNS_DATA_DIR" "$CNS_DATA_DIR/keys" "$CNS_DATA_DIR/keys/users"
chmod 600 "$CNS_DATA_DIR/keys/aes_master.key" "$CNS_DATA_DIR"/keys/users/*.wrapped
```

This copies the existing database, key material, stored files, certificates, and backups without changing or regenerating them. Verify the copy and keep the backup before restarting. Set the instance and TLS paths for this Ubuntu shell:

```bash
export CNS_INSTANCE_DIR="$CNS_DATA_DIR"
export TLS_CERT_FILE="$CNS_DATA_DIR/tls/lab.crt"
export TLS_KEY_FILE="$CNS_DATA_DIR/tls/lab.key"
export REQUIRE_HTTPS=1
export SESSION_COOKIE_SECURE=1
export APP_HOST=0.0.0.0
export APP_PORT=5000
```

If the copied TLS certificate/key pair does not exist, generate one into the local instance directory. The script refuses to overwrite existing files:

```bash
python3 scripts/generate_lab_tls.py --ip 192.168.56.102 --output "$CNS_DATA_DIR/tls"
```

Copy only `lab.crt` to Windows and Kali and trust it there. Never copy `lab.key` off Ubuntu. Environment variables exported in this shell take precedence over values in the project's `.env`; keep the existing `.env`, database, and keys intact. Re-export these variables in each new shell before starting the app.

## Install scanner and start Flask

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip clamav clamav-freshclam
sudo systemctl enable --now clamav-freshclam
systemctl status clamav-freshclam --no-pager
clamscan --version
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

`freshclam` is the signature updater service; `clamscan` is the scanner used for uploaded files. Let the service update its databases. Do not run `sudo freshclam` while `clamav-freshclam` is already holding the updater lock. For a deliberate one-time manual update only, stop the service, run `sudo freshclam`, then start the service again. A `NotifyClamd` message about missing `/etc/clamav/clamd.conf` is not fatal for this app because it invokes `clamscan`, not the `clamd` daemon. Failed scans are never accepted as clean.

The 120-second default allows a cold `clamscan` process to load signatures on a small VM. If the upload still times out, set `CLAMSCAN_TIMEOUT=240` in the Ubuntu environment and restart Flask; do not weaken the failed-scan rejection behavior.

## Browser URLs and workflow

With the HTTPS setup above, use the same exact origin on Windows, Kali, and Ubuntu:

- Windows user portal: `https://192.168.56.102:5000/login`
- Kali user portal: `https://192.168.56.102:5000/login`
- Ubuntu administrator dashboard: `https://192.168.56.102:5000/dashboard`
- Ubuntu attacker console: `https://192.168.56.102:5000/attacker` (administrator account only)
- Diagnostics: `https://192.168.56.102:5000/api/diagnostics`
- Virus Detection: `https://192.168.56.102:5000/virus-scanner`
- File Sharing: `https://192.168.56.102:5000/files`
- Events and report: `https://192.168.56.102:5000/events` and `/events.csv`
- Notifications: `https://192.168.56.102:5000/notifications`
- Chart data: `https://192.168.56.102:5000/api/dashboard/metrics?days=7`

The relay page is standalone and now explicitly loads the shared CSRF-aware JSON helper before its relay controls. If a browser form has been left open for more than the one-hour CSRF token lifetime, reload it and submit again. Do not disable CSRF to work around an expired token.

Register the configured admin username on Ubuntu first, then create one ordinary account for the Windows user and a second ordinary account for Kali. A message sent while protection is disabled on both endpoints enters Ubuntu's manual relay. If only one endpoint enables protection, the server refuses the send instead of silently using plaintext. Forward an unprotected queued message unchanged, forward an edited copy, or drop it from the Ubuntu attacker console; only a forwarded message is delivered. Edited forwarding is blocked if either user enables protection after queueing. The Windows/Kali browser crypto flow requires trusted HTTPS. Do not open an `https://` URL when Flask is listening as HTTP (or vice versa): TLS bytes sent to an HTTP server create binary-looking 400 log entries and the session/token origins will not match. The diagnostics page reports the actual request scheme, host, port, TLS configuration, and secure-cookie mismatch.

## Data and source paths

| Data | Default when launched from source root | Recommended live Ubuntu path |
|---|---|---|
| Source code edited on Windows | `/media/sf_cnsproject/cns-security-lab` | Same shared source folder |
| SQLite database | `instance/cns_lab.db` | `$HOME/.local/share/cns-security-lab/cns_lab.db` |
| AES/Ed25519 keys | `instance/keys/` | `$HOME/.local/share/cns-security-lab/keys/` |
| Private uploaded files | `instance/shared-files/` | `$HOME/.local/share/cns-security-lab/shared-files/` |
| Scan temporary files | `instance/scanner-tmp/` | `$HOME/.local/share/cns-security-lab/scanner-tmp/` |
| TLS certificate and private key | `.env` TLS paths (often `instance/tls/`) | `$HOME/.local/share/cns-security-lab/tls/` |

The code continues to be edited in the shared source tree; the running Ubuntu process sees edits at that same path. Keep exactly one Flask process running. Do not run Flask debug reloaders alongside the normal server, and do not run `scripts/init_db.py` to fix an existing instance; it is for controlled first-time initialization and the app already applies its supported additive upgrades with a backup.
