#!/usr/bin/env python3
"""Generate a local self-signed TLS certificate for an isolated CNS lab VM."""
import argparse
import os
import shutil
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default="192.168.56.102", help="Ubuntu VM host-only IP")
    parser.add_argument("--output", default="instance/tls")
    args = parser.parse_args()
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("OpenSSL is required. Install it with: sudo apt install openssl")
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    cert, key = out / "lab.crt", out / "lab.key"
    if cert.exists() or key.exists():
        raise SystemExit(f"Refusing to overwrite existing TLS files in {out}")
    subprocess.run([
        openssl, "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256",
        "-days", "365", "-keyout", str(key), "-out", str(cert),
        "-subj", f"/CN={args.ip}", "-addext",
        f"subjectAltName=IP:{args.ip},IP:127.0.0.1,DNS:localhost",
    ], check=True)
    try:
        os.chmod(key, 0o600)
        os.chmod(out, 0o700)
    except OSError:
        pass
    print(f"Created certificate: {cert}")
    print(f"Created private key: {key}")
    print("Copy only the .crt certificate to Windows/Kali and trust it for this isolated lab.")


if __name__ == "__main__":
    main()
