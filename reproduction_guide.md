# CNS Security Lab Research Artifacts: Reproduction Guide

## Scope and environment

The included measurement run was performed on the Windows development host using Python 3.14.7, pytest 9.1.1, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, cryptography 50.0.2, and ReportLab 4.5.1. It is not a measurement from the Ubuntu/Kali/Windows VM network. The pytest suite uses isolated temporary databases and keys. The crypto benchmark calls the project's actual `services.crypto` functions directly; it does not make HTTP requests or access the project's live `instance/` data.

## Recreate test evidence

From the project root on Windows PowerShell:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pytest -q --tb=short --junitxml=docs\pytest-results-current.xml --basetemp=docs\pytest-tmp-current
.venv\Scripts\python.exe analysis.py --junit docs\pytest-results-current.xml
```

The JUnit report stores each collected test case, its outcome, and duration. `analysis.py` converts it to `experimental_data.csv`, computes summary statistics, and regenerates the outcome/runtime PDFs. A platform-specific file-permission case is expected to skip on Windows and should be run on Ubuntu/POSIX to evaluate file modes. The suite reported 114 cases, 113 passed, one skipped, zero failed, and 108.395 s in the recorded run. Test totals can change when the source test suite changes.

On Ubuntu, install the OS scanner separately if running the whole app:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip clamav clamav-freshclam
sudo systemctl enable --now clamav-freshclam
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pytest -q --tb=short --junitxml=docs/pytest-results-current.xml --basetemp=docs/pytest-tmp-current
python3 analysis.py --junit docs/pytest-results-current.xml
```

The ClamAV daemon/updater setup is not required for the unit suite itself. The app invokes `clamscan`; tests may mock or bypass external scanner behavior. Do not expose the development listener to a public network.

## Recreate cryptographic timing measurements

```powershell
.venv\Scripts\python.exe benchmark_crypto.py
.venv\Scripts\python.exe analysis.py --junit docs\pytest-results-current.xml --crypto crypto_benchmark.csv
```

The benchmark uses a fresh temporary random master key and Ed25519 keypair per run. It measures `encrypt_and_sign` and `decrypt_envelope` at 16, 256, 1024, and 2000 ASCII bytes, 100 trials per payload-size/operation/mode. The paired AES-GCM-only baseline uses the same AES key and payload size, precomputed associated data taken from a valid prepared envelope, a reused AESGCM instance, and a nonce generated before timing; it omits metadata creation, nonce generation, Ed25519 signature generation/verification, and service/network/database operations. Trial order is randomized. The output file records UTC run time, Python and cryptography versions, operating-system string, mode, size, trial number, operation, and raw nanoseconds.

`analysis.py` reports mean, median, sample standard deviation, nearest-rank 95th percentile, and a percentile-bootstrap interval for the median using 2000 deterministic resamples. This is a descriptive local benchmark; repeat on each target host and retain each raw CSV before making cross-machine comparisons. The bootstrap interval does not capture between-run, operating-system, hardware, thermal, or interpreter variation.

## Data and graph meanings

- `experimental_data.csv`: one row per JUnit test case. `outcome` is pass/skip/fail; `duration_seconds` is pytest-reported test-harness time.
- `crypto_benchmark.csv`: one row per timed operation, including all 1600 individual trials.
- `crypto_benchmark_summary.csv`: aggregated groups by operation, payload size, and mode.
- `analysis_summary.json`: run-level and test-suite summary.
- `figures/test_outcomes.pdf`: monochrome counts of regression cases.
- `figures/test_runtime_by_module.pdf`: summed JUnit case duration per test module.
- `figures/crypto_overhead.pdf`: full envelope routine versus primitive-only AES-GCM baseline, medians and bootstrap intervals.
- `docs/pytest-results-current.xml`: raw JUnit test report for the recorded suite.

The test-outcome graph is not an attack-blocking rate. Crypto measurements are not HTTP response latency or end-to-end security overhead. No scanner precision/recall/F1 is calculated because no independently labeled vulnerable/benign target corpus exists.

## Proposed security experiments

1. **Tamper mutation matrix:** create a clean instance, send known messages, and mutate ciphertext, tag, signature, nonce, sender, recipient, UUID, timestamp, and algorithm independently. Record attempt ID, mutation, API status, verification state, plaintext-release boolean, and database row. Use no plaintext release as the required failure criterion.
2. **Authorization/ID enumeration:** create sender, recipient, and third-party accounts. For each known and nonexistent message identifier, test HTML, API body, and envelope routes. Record status, response length, plaintext sentinel presence, and access-denied event. Compare forbidden and missing identifiers; don't infer protection beyond exercised routes.
3. **CSRF/session test:** with a CSRF-enabled app and valid authenticated session, submit each mutating route with missing, invalid, and valid token; then revoke/logout and replay the old cookie. Record response status and session-validity check. Enumerate every POST/PUT/PATCH/DELETE route from the current route map.
4. **HTTP-level performance:** instrument request boundaries and service phases. For each payload size (e.g., 16, 256, 1024, 2000 bytes), execute at least 100 paired protected/unprotected requests on the same host, randomize order, warm up first, use fresh database rows, and record status and monotonic elapsed time. Separate request, crypto, database, and transport durations. Define a baseline carefully; the existing unprotected path has different relay behavior, so it is not a pure crypto-off control.
5. **Website scanner accuracy:** build a local owned fixture with a written ground-truth manifest for supported headers, redirects, cookie flags, CORS, and fixed-path exposure. Production SSRF rules block loopback; test via mocked DNS/HTTP transports or a dedicated isolated test-only override without weakening production target checks. Record every request and finding. Only after labeling each case can TP/TN/FP/FN, precision, recall, and F1 be computed.
6. **Ubuntu VM and ClamAV:** record Ubuntu release/kernel, Python/package versions, ClamAV engine/signature versions, VM CPU/RAM, TLS certificate trust on both clients, file sizes and type, scan status, and durations. Use harmless test fixtures such as the standard EICAR test string only in a disposable isolated VM, and never use real malware samples on a general-purpose host.

For all experiments, test only locally controlled or explicitly authorized assets. Preserve raw observations, software versions, exact commands, configuration, and failures. Avoid calling a passing test suite a security proof.

## IEEE compilation

`research_paper.tex` uses `\\documentclass[conference]{IEEEtran}` and `\\bibliographystyle{IEEEtran}`. The current environment did not have `pdflatex`, `latexmk`, or `tectonic`, so PDF compilation and final visual overflow checks were unavailable. To compile, create an IEEE Conference project from the official IEEE Author Center/Overleaf IEEE conference template, upload `research_paper.tex`, `references.bib`, and all PDFs in `figures/`, then compile with the template's supported LaTeX engine and BibTeX. Review the generated PDF against the selected conference's page limit, accessibility, figure legibility, font embedding, and final-submission rules. No target conference has been specified, so venue-specific instructions and page limits remain to be checked.
