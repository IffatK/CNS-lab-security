# IEEE Paper and Research Artifact Validation

Validation date: 2026-10-17 (local workstation date)

## Completed checks

- [x] Main source uses `\\documentclass[conference]{IEEEtran}`, the IEEE numeric citation package, IEEE bibliography style, conference author-block structure, abstract, and index terms.
- [x] The source delegates page layout, column dimensions, heading appearance, and type hierarchy to the `IEEEtran` conference class; no custom page margins or colored design are specified.
- [x] Main source uses black-and-white vector PDF figures. Test outcomes, test-module runtime, and actual cryptographic-function timings are cited in the text and captions.
- [x] Abstract is a single paragraph, under 250 words, without citations or equations. The author identity/affiliation fields are clearly marked for completion because the author details were not supplied.
- [x] Equations describe the verified source: AES-GCM uses the single application master key; Ed25519 signs domain-separated metadata/nonce/ciphertext; signature verification precedes decryption; browser transport uses RFC 3526 Group 5 and terminates at the server.
- [x] Technical claims distinguish implemented code, test assertions, local microbenchmark results, and proposed future experiments.
- [x] Numbered citations in `research_paper.tex` map to entries in `references.bib`; sources include IEEE Xplore/official author guidance, NIST, RFC Editor, OWASP, Flask, PyCA, and ClamAV documentation.
- [x] Test evidence was collected from `docs/pytest-results-current.xml`: 114 cases, 113 passed, one skipped, zero failed; suite time 108.395 seconds. The skipped test is POSIX file permissions.
- [x] The declared requirements were installed in the project virtual environment after the first run revealed ReportLab was missing; the PDF export test passed on the dependency-complete rerun.
- [x] `experimental_data.csv` contains 114 raw per-case JUnit observations. `crypto_benchmark.csv` contains 1600 raw timing observations (4 payload sizes x 2 operations x 2 modes x 100 trials). Derived CSV, JSON, and graph files are reproducible with `analysis.py`.
- [x] `benchmark_crypto.py` and `analysis.py` pass Python `compileall`; the analysis script executed and generated the current summaries and figures.
- [x] The three vector PDF figures were rasterized with Poppler for visual inspection; labels, units, grayscale distinctions, legends, captions, and plot spacing were reviewed. The cryptographic plot legend was adjusted to separate it from the x-axis labels.
- [x] Citation keys and LaTeX labels/references were checked programmatically; all 13 cited keys are present in the BibTeX file and every in-text cross-reference resolves to a label.
- [x] The repository's `docs/test-results.txt` was updated to the current dependency-complete run; the raw JUnit report is retained separately.
- [x] An initial full test run failed only in PDF export because ReportLab was absent, and passed after installation from `requirements.txt`; that first-run result is documented in the paper/reproduction notes.

## Not verified / outstanding before submission

- [ ] PDF compilation and visual layout inspection: no `pdflatex`, `latexmk`, or `tectonic` executable was available on the current host. Therefore page breaks, overfull boxes, final figure placement, and equation rendering have not been inspected in a compiled PDF.
- [ ] Local copy/version of `IEEEtran.cls` and `IEEEtran.bst`: the LaTeX source invokes the official class/style; compile using a fresh IEEE conference template project to ensure current class files are supplied.
- [ ] PDF embedded fonts: no PDF was generated here, so embedding cannot be inspected.
- [ ] Conference-specific page limit, paper size option, anonymity, and supplemental-material rules: no target conference was named.
- [ ] Word version: no updated `research_paper.docx` was generated because the requested primary deliverable is IEEEtran LaTeX and the official editable IEEE Word template is not available locally.
- [ ] Ubuntu/POSIX file permission test, three-VM network/TLS trust, real ClamAV scan duration, and authorized live scanner behavior were not run in this Windows test environment.
- [ ] The crypto microbenchmark is a single workstation run. It is not a latency benchmark for the HTTP application or Ubuntu server and does not establish cross-platform statistical significance.
- [ ] No independently labeled vulnerability corpus exists; scanner precision/recall/F1, attack-blocking rate, and confusion matrix are intentionally absent.

## Build and data integrity notes

- `research_paper.pdf` is not included because a LaTeX toolchain was unavailable. `reproduction_guide.md` describes compilation in an official IEEE conference template project.
- The 114-case test CSV row count and 1600 timing-row count were checked against the run parameters. The plots are generated directly from those raw observations, not hand-entered illustrative values.
- This paper is a technically detailed project study, not a claim of comprehensive security certification. Replace author placeholders and apply the selected conference's current submission instructions before submission.
