# Testing

## 1. Automated (pytest, on Ubuntu or Windows)
`python3 -m pytest` - 78 collected tests: auth, cryptography, messaging, authorization/IDOR, CSRF, relay behavior,
scanner integration, private file sharing, session revocation, SQLi, headers, tamper-at-rest, key permissions,
non-regeneration, log hygiene, dashboard metric scoping, diagnostics, date-filtered reporting, and user-scoped security
notifications, and additive migration backup/preservation. Tests use temporary databases and keys, never the project's `instance/`. The latest full Windows run completed with
77 passed and 1 skipped; the skipped check covers POSIX-only file permissions. Run tests again after local changes;
`docs/test-results.txt` records the last checked run.

## 2. Kali network tests (live server only)
```
python3 kali/lab_tests.py                  # target is fixed to 192.168.56.102:5000; other hosts are refused
```
Creates 5 throwaway accounts (`kali_a_xxxxxx` ...) and a few test messages on the target; nothing is deleted.
Every line prints *expected* and *observed* from real responses, and the run is saved to `kali/results/*.json`.

| ID | What is exercised | Expected |
|---|---|---|
| T01 | `/api/health` | 200, status ok |
| T02-T03 | register/login, wrong credentials, unknown user | 302; 401 with identical message |
| T04 | protected pages/APIs without login | 302 / 401 |
| T05a-d | send, authorised read, IDOR by third user, id sweep | 201; 200 verified; 404; only 404 |
| T06 | SQLi strings in login, register, recipient, query, path | no 5xx, no bypass, DB intact |
| T07 | CSRF: no token / forged token / logout without token | 400 each; session survives |
| T08 | cookie flags; replay of cookie after logout | HttpOnly+SameSite; 401 |
| T09 | `/api/verify` with flipped ciphertext/signature/nonce, changed recipient/time | only unmodified is valid |
| T10 | 404, malformed JSON, oversized body | 404/400/413, no traceback |
| T11 | 8 bad logins for a nonexistent user | 5x401 then 429 + Retry-After |

Manual extras on the isolated host-only network: `nmap -p 5000 -sV 192.168.56.102`, `curl -k -i https://192.168.56.102:5000/api/health`.
Do not point these tools at anything except 192.168.56.102.

## 3. Traffic capture
Terminal 1: `sudo kali/capture_traffic.sh 60`. Terminal 2: run T-tests or use the browser from Kali/Windows.
Then `kali/analyze_capture.sh kali/captures/<file>.pcap` and open the pcap in Wireshark (`tls`, `tls.handshake`,
or `http` only if intentionally testing an isolated legacy HTTP configuration). Under HTTPS, application request bodies
are encrypted on the network; the Ubuntu relay can still inspect the intentionally plaintext relay path after TLS
termination. At rest (`sqlite3 instance/cns_lab.db "select hex(ciphertext) from messages"`) stored messages are ciphertext.

## 4. Lab page (in-app)
`/lab` runs 7 live crypto checks (round trip, ciphertext/signature/metadata tamper, wrong key, nonce uniqueness over 2000
encryptions, audit of stored messages). Outcomes are logged as `lab_test` events.
