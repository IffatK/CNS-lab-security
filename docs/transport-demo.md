# Message transport and manual relay demonstration

This is an educational exercise on the private three-VM host-only network: Windows and Kali use the user portal; Ubuntu runs Flask, stores the keys and database, and hosts the admin-only attacker console.

## Message flow

- With both users' protection settings enabled, the browser encrypts the body before sending it to Ubuntu using the educational transport scheme. HTTPS is required for browser cryptography. Ubuntu terminates this protection and then stores an AES-GCM encrypted, Ed25519-signed envelope; this is not E2EE.
- If both users have protection off, the body is sent through the intentionally visible lab path and held in Ubuntu's interception queue. It is not delivered until the authorized Ubuntu operator forwards the unchanged message, forwards a modified copy, or drops it. If only one account has protection enabled, sending through the plaintext relay is refused; there is no silent fallback.
- The sender signs the original envelope before it reaches the queue. Forwarding unchanged preserves that exact envelope and signature. Forwarding edited content changes the encrypted bytes while retaining the original signature; the recipient sees `TAMPERED — NOT VERIFIED`, and no plaintext is returned. The relay does not sign edited content as the sender.
- Dropped messages are never inserted into the recipient's mailbox. Duplicate and invalid queue transitions are rejected, and relay actions are audited.

## Demo on the three VMs

1. Start the HTTPS app on Ubuntu and open the user portal on Windows and Kali. Trust the local public certificate on both client VMs.
2. Register an admin account (from the configured admin username allowlist), plus one user for Windows and another for Kali.
3. Submit an unprotected message from Windows to the Kali user. It should appear in the pending queue on Ubuntu `/attacker`, not in the recipient inbox.
4. As admin on Ubuntu, forward unchanged and observe the `UNPROTECTED RELAY` notice; repeat with an edited body and observe `TAMPERED — NOT VERIFIED` with plaintext withheld; then repeat and drop to confirm no recipient delivery. If either account enables protection after a message is queued, the server blocks edited forwarding and records the attempt.
5. Enable transport protection on both accounts and send again. The protected submission bypasses the manual plaintext queue. The server still holds the key and is trusted for this simulation.

## Boundaries

The attacker console is app-scoped; it does not monitor unrelated traffic, browser history, or other applications. Server-side keys mean the Ubuntu administrator remains inside the trust boundary. The finite-field ElGamal exercise is not suitable for real security protocols. Keep the development server on the isolated host-only network.
