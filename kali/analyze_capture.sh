#!/usr/bin/env bash
# Show what an on-path observer sees in a capture. Usage: ./analyze_capture.sh file.pcap
set -euo pipefail
F="${1:?pcap file}"
echo "== Packets: $(tcpdump -nn -r "$F" 2>/dev/null | wc -l)"
echo "== HTTP requests (method, path)"
tcpdump -nn -A -r "$F" 2>/dev/null | grep -aE '^(GET|POST|PUT|DELETE) ' | sort | uniq -c | sort -rn | head -30
echo "== Cleartext form/JSON credentials and message bodies visible on the wire (redacted to key names + length)"
tcpdump -nn -A -r "$F" 2>/dev/null | grep -aoE '(password|confirm|csrf_token|body|recipient)(=|":")[^&" ]{0,200}' \
  | sed -E 's/((password|confirm)(=|":"))[^&" ]+/\1<REDACTED-BUT-VISIBLE>/' | sort | uniq -c | head -20
echo "== Session cookies observed in Set-Cookie / Cookie headers (names only)"
tcpdump -nn -A -r "$F" 2>/dev/null | grep -aoE '(Set-Cookie|Cookie): session=' | sort | uniq -c
if command -v tshark >/dev/null; then
  echo "== tshark HTTP summary"; tshark -r "$F" -Y http.request -T fields -e frame.number -e http.request.method -e http.request.uri 2>/dev/null | head -40
fi
echo
echo "Interpretation: the lab serves plain HTTP. AES-GCM protects messages at rest in SQLite, NOT on the wire;"
echo "an observer on the host-only network sees credentials and plaintext message bodies. See docs/limitations.md."
