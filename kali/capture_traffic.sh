#!/usr/bin/env bash
# Capture lab traffic on Kali (needs sudo). Usage: sudo ./capture_traffic.sh [seconds]
# Run lab_tests.py (or browse the app) from another terminal while this runs.
set -euo pipefail
TARGET=192.168.56.102; KALI=192.168.56.101; PORT=5000; SECS="${1:-60}"
IFACE=$(ip -br addr | awk -v ip="$KALI" '$0 ~ ip {print $1; exit}')
[ -n "$IFACE" ] || { echo "No interface has $KALI; set IFACE manually"; exit 1; }
mkdir -p "$(dirname "$0")/captures"
OUT="$(dirname "$0")/captures/cns_$(date +%Y%m%d-%H%M%S).pcap"
echo "Capturing on $IFACE for ${SECS}s: host $TARGET and tcp port $PORT -> $OUT"
timeout "$SECS" tcpdump -i "$IFACE" -s 0 -w "$OUT" "host $TARGET and tcp port $PORT" || true
echo "Saved $OUT ($(stat -c %s "$OUT") bytes). Analyse with: ./analyze_capture.sh $OUT"
