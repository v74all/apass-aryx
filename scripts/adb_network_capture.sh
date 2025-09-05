#!/usr/bin/env bash


set -euo pipefail

DEVICE="${DEVICE:-${1:-}}"
PACKAGE="${PACKAGE:-${2:-}}"
DURATION="${DURATION:-120}"

if [[ -z "$DEVICE" || -z "$PACKAGE" ]]; then
  echo "Usage: DEVICE=<serial> PACKAGE=<pkg> [DURATION=120] $0" >&2
  exit 2
fi

ROOT_DIR="$(cd -- "$(dirname -- "$0")/.." >/dev/null 2>&1 && pwd)"
TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$ROOT_DIR/analysis_results/unified_output/dynamic_adb_${TS}"
mkdir -p "$OUT_DIR/network" "$OUT_DIR/logs" "$OUT_DIR/screenshots"

echo "[+] Output: $OUT_DIR"

echo "[+] Launching $PACKAGE on $DEVICE"
adb -s "$DEVICE" shell monkey -p "$PACKAGE" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
sleep 2

PID="$(adb -s "$DEVICE" shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r' || true)"
APP_UID="$(adb -s "$DEVICE" shell dumpsys package "$PACKAGE" | sed -n 's/.*userId=\([0-9]*\).*/\1/p' | head -n1 | tr -d '\r' || true)"
echo "PID=$PID" | tee "$OUT_DIR/logs/session.info"
echo "APP_UID=$APP_UID" | tee -a "$OUT_DIR/logs/session.info"

echo "[+] Capturing snapshots (before)"
adb -s "$DEVICE" shell dumpsys netstats > "$OUT_DIR/network/dumpsys_netstats_before.txt" || true
adb -s "$DEVICE" shell dumpsys connectivity > "$OUT_DIR/network/dumpsys_connectivity.txt" || true
adb -s "$DEVICE" shell getprop | grep -iE 'dns|http|https|proxy' > "$OUT_DIR/network/device_props.txt" || true
if [[ -n "$PID" ]]; then
  for f in tcp tcp6 udp udp6; do adb -s "$DEVICE" shell "cat /proc/$PID/net/$f 2>/dev/null || true" > "$OUT_DIR/network/proc_${f}_before.txt" || true; done
fi

CAP_ALL="$OUT_DIR/network/logcat_all.log"
CAP_APP="$OUT_DIR/network/logcat_${PID:-na}.log"
echo "[+] Starting logcat capture for ${DURATION}s"
(
  timeout "$DURATION" adb -s "$DEVICE" logcat -v time > "$CAP_ALL" 2>/dev/null || true
) &
LC_ALL_PID=$!

if [[ -n "$PID" ]]; then
  (
    timeout "$DURATION" adb -s "$DEVICE" logcat --pid "$PID" -v time > "$CAP_APP" 2>/dev/null || true
  ) &
  LC_APP_PID=$!
fi

echo "[+] Driving UI with monkey to stimulate traffic"
adb -s "$DEVICE" shell monkey -p "$PACKAGE" --pct-touch 80 --pct-appswitch 5 --pct-anyevent 15 --throttle 300 -v 600 > "$OUT_DIR/logs/monkey.log" 2>&1 || true

wait "$LC_ALL_PID" || true
if [[ -n "${LC_APP_PID:-}" ]]; then wait "$LC_APP_PID" || true; fi

echo "[+] Capturing snapshots (after)"
adb -s "$DEVICE" shell dumpsys netstats > "$OUT_DIR/network/dumpsys_netstats_after.txt" || true
if [[ -n "$PID" ]]; then
  for f in tcp tcp6 udp udp6; do adb -s "$DEVICE" shell "cat /proc/$PID/net/$f 2>/dev/null || true" > "$OUT_DIR/network/proc_${f}_after.txt" || true; done
fi

echo "[+] Parsing logs for URLs/domains"
python3 - <<'PY'
import re, json, sys, pathlib
from urllib.parse import urlparse
out = pathlib.Path(sys.argv[1]); net = out/"network"
cap_app = next((p for p in net.glob('logcat_*.log') if p.name!='logcat_all.log'), None)
data = ''
if cap_app and cap_app.exists():
    data = cap_app.read_text(errors='ignore')
elif (net/"logcat_all.log").exists():
    data = (net/"logcat_all.log").read_text(errors='ignore')

urls = set(re.findall(r'https?://[^\s\]\)\("\']+', data, flags=re.I))
domains = set()
for u in urls:
    try:
        h = urlparse(u).hostname
        if h: domains.add(h)
    except: pass
domains |= set(re.findall(r'\bHost:\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b', data, flags=re.I))
pat = re.compile(r'^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
domains = {d.strip('.').lower() for d in domains if pat.match(d)}
(net/"urls.txt").write_text("\n".join(sorted(urls)))
(net/"domains.txt").write_text("\n".join(sorted(domains)))
summary = {"urls_count": len(urls), "domains_count": len(domains), "example_urls": sorted(list(urls))[:10], "example_domains": sorted(list(domains))[:20]}
(out/"network_summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
PY
"$OUT_DIR"

echo "[+] Done: $OUT_DIR"
