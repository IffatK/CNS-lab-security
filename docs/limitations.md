# Security limitations

1. **Not end-to-end encrypted.** Ubuntu owns the master AES key and users' server-side Ed25519 signing keys. A server administrator can decrypt messages and the server can perform signing operations.
2. **Browser transport encryption is educational.** Its ElGamal finite-field scheme is not a production protocol; it terminates on Ubuntu. Do not use it for real confidential communication.
3. **The Flask development server is not production hosting.** It is suitable only for the isolated lab. Do not expose it to public or bridged networks.
4. **The generated certificate is self-signed.** Trust the public certificate only on the isolated Windows and Kali VMs. Keep the private key on Ubuntu and replace the certificate deliberately before expiry.
5. **ClamAV needs local setup.** The app does not download signatures automatically; update them with `freshclam`. Unsupported formats and scan failures are rejected. A clean antivirus result is not a guarantee that a file is harmless.
6. **File SHA-256 checks detect accidental or unauthorized changes relative to stored metadata; they do not encrypt the file or prevent an administrator with DB and filesystem access from replacing both.**
7. **Session device labels are estimates from user-agent and source IP.** They do not identify a physical device or exact location.
8. **Audit events are application-level records.** A host administrator can alter the SQLite database; there is no remote append-only log or external alerting integration.
9. **No standalone read/unread notification center or TOTP MFA is implemented.** Relevant security activity is surfaced through the dashboard and searchable audit pages.
10. **Registration is open by default.** The configured `ADMIN_USERNAMES` list determines which usernames receive the admin role during registration; restrict the isolated lab network accordingly.

Use throwaway accounts and data. Do not use live malware samples; test scanner integration with mocks or the standard EICAR test string only in a controlled scanner test environment.
