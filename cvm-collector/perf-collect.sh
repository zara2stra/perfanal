#!/bin/bash
set -euo pipefail

DURATION=10
FREQUENCY=99
CLUSTER_ID=""
OUTPUT_DIR="/home/nutanix/tmp"

usage() {
    cat <<'USAGE'
Usage: perf-collect.sh --cluster-id <ID> [OPTIONS]

Collect perf profiling data on a Nutanix CVM and package it for analysis.
Always captures system-wide. Use the analyzer's web UI to filter by process.

Required:
  --cluster-id <ID>     Cluster identifier (used for tracking in the analyzer)

Options:
  --duration <SEC>      Sampling duration in seconds  (default: 10)
  --frequency <HZ>      Sampling frequency in Hz      (default: 99)
  --output-dir <DIR>    Output directory               (default: /home/nutanix/tmp)
  -h, --help            Show this help message

Examples:
  ./perf-collect.sh --cluster-id prod-01
  ./perf-collect.sh --cluster-id prod-01 --duration 30 --frequency 199
USAGE
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cluster-id)   CLUSTER_ID="$2";   shift 2 ;;
        --duration)     DURATION="$2";     shift 2 ;;
        --frequency)    FREQUENCY="$2";    shift 2 ;;
        --output-dir)   OUTPUT_DIR="$2";   shift 2 ;;
        -h|--help)      usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$CLUSTER_ID" ]]; then
    echo "ERROR: --cluster-id is required"
    usage
fi

mkdir -p "$OUTPUT_DIR"
export TMPDIR="$OUTPUT_DIR"

HOSTNAME_SHORT=$(hostname -s)
TIMESTAMP=$(date +'%Y-%m-%d-%H-%M-%S')
BUNDLE_NAME="perf-bundle-${CLUSTER_ID}-${HOSTNAME_SHORT}-${TIMESTAMP}"
WORK_DIR="${OUTPUT_DIR}/${BUNDLE_NAME}"
mkdir -p "$WORK_DIR"

trap 'sudo rm -rf "$WORK_DIR"' EXIT

echo "=== Perf Collector ==="
echo "Cluster ID : $CLUSTER_ID"
echo "Hostname   : $HOSTNAME_SHORT"
echo "Duration   : ${DURATION}s"
echo "Frequency  : ${FREQUENCY} Hz"
echo "Mode       : system-wide"
echo "Working dir: $WORK_DIR"
echo ""

PERF_BIN="${WORK_DIR}/perf.data"

# CVMs run inside a VM where hardware PMU counters (cycles) are unavailable.
# Per-PID capture with software events also produces zero samples on these kernels.
# Always capture system-wide with cpu-clock; filtering happens in the analyzer.
EVENT="cpu-clock"

echo "[1/7] Starting iostat sampling (1s intervals)..."
iostat -dxy 1 > "${WORK_DIR}/iostat_data.txt" 2>/dev/null &
IOSTAT_PID=$!
echo "       iostat PID: $IOSTAT_PID"

echo "[2/7] Recording perf data (${DURATION}s, event=${EVENT})..."

# Use --call-graph dwarf for accurate userspace stack unwinding.
# The default -g uses frame-pointer unwinding which fails on optimized
# Nutanix binaries (-fomit-frame-pointer), producing hex-only "[unknown]" frames.
# DWARF uses CFI unwind tables that exist even in stripped/optimized binaries.
CALLGRAPH="dwarf"

# Fall back to frame-pointer if dwarf is not supported on this kernel
if ! sudo perf record --call-graph dwarf -e "$EVENT" -o /dev/null -- sleep 0 2>/dev/null; then
    echo "       DWARF call-graph not available, falling back to frame-pointer (-g)"
    CALLGRAPH="fp"
fi

echo "       sudo perf record -F $FREQUENCY -e $EVENT -a --call-graph $CALLGRAPH -o ... -- sleep $DURATION"
sudo TMPDIR="$OUTPUT_DIR" perf record -F "$FREQUENCY" -e "$EVENT" -a --call-graph "$CALLGRAPH" --no-buildid-cache -o "$PERF_BIN" -- sleep "$DURATION" 2>&1 | tee "${WORK_DIR}/perf_record.log"

if [[ ! -s "$PERF_BIN" ]]; then
    echo "ERROR: perf.data is empty or missing. perf record may have failed."
    echo "       perf_event_paranoid = $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 'unknown')"
    ls -la "$PERF_BIN" 2>/dev/null || echo "       File does not exist"
    exit 1
fi

echo "       perf.data size: $(du -h "$PERF_BIN" | cut -f1)"

kill "$IOSTAT_PID" 2>/dev/null || true
wait "$IOSTAT_PID" 2>/dev/null || true
echo "       iostat samples collected: $(grep -c '^[a-zA-Z]' "${WORK_DIR}/iostat_data.txt" 2>/dev/null || echo 0) device-rows"

echo "[3/7] Generating perf script output..."
sudo perf script -i "$PERF_BIN" > "${WORK_DIR}/perf_threads.txt" 2>"${WORK_DIR}/perf_script.log"

PERF_THREADS_SIZE=$(stat -c%s "${WORK_DIR}/perf_threads.txt" 2>/dev/null || stat -f%z "${WORK_DIR}/perf_threads.txt" 2>/dev/null || echo "0")
echo "       perf_threads.txt size: ${PERF_THREADS_SIZE} bytes"

if [[ "$PERF_THREADS_SIZE" -eq 0 ]]; then
    echo ""
    echo "WARNING: perf script produced empty output."
    echo "         perf record log:"
    cat "${WORK_DIR}/perf_record.log" 2>/dev/null || true
    echo ""
    echo "         perf script stderr:"
    cat "${WORK_DIR}/perf_script.log" 2>/dev/null || true
    echo ""
    echo "         Trying alternative: sudo perf script (from perf.data dir)..."
    pushd "$WORK_DIR" > /dev/null
    sudo perf script > "${WORK_DIR}/perf_threads.txt" 2>>"${WORK_DIR}/perf_script.log"
    popd > /dev/null
    PERF_THREADS_SIZE=$(stat -c%s "${WORK_DIR}/perf_threads.txt" 2>/dev/null || stat -f%z "${WORK_DIR}/perf_threads.txt" 2>/dev/null || echo "0")
    echo "         Retry result: ${PERF_THREADS_SIZE} bytes"

    if [[ "$PERF_THREADS_SIZE" -eq 0 ]]; then
        echo ""
        echo "ERROR: perf script produced no output even on retry."
        echo "       The perf.data file may contain no samples."
        echo "       Try manually: sudo perf report -i $PERF_BIN"
        echo "       Bundling what we have (metadata + logs) for debugging."
    fi
fi

echo "[4/7] Collecting system metadata..."

python3 - "$CLUSTER_ID" "$HOSTNAME_SHORT" "$TIMESTAMP" "$DURATION" "$FREQUENCY" "${WORK_DIR}/metadata.json" <<'PYEOF'
import json, platform, os, sys, subprocess

cluster_id  = sys.argv[1]
hostname    = sys.argv[2]
timestamp   = sys.argv[3]
duration    = int(sys.argv[4])
frequency   = int(sys.argv[5])
output_path = sys.argv[6]

cpu_info = "unknown"
try:
    with open("/proc/cpuinfo") as f:
        for line in f:
            if line.startswith("model name"):
                cpu_info = line.split(":", 1)[1].strip()
                break
except Exception:
    pass

cpu_count = os.cpu_count() or 0

mem_total = "unknown"
try:
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemTotal"):
                mem_total = line.split(":", 1)[1].strip()
                break
except Exception:
    pass

kernel = platform.release()

services = {}
svc_names = [
    "genesis", "stargate", "cassandra", "curator",
    "chronos", "cerebro", "acropolis", "prism", "zookeeper",
]
for svc in svc_names:
    try:
        out = subprocess.run(
            ["pgrep", "-f", svc],
            capture_output=True, text=True, timeout=5
        )
        pids = out.stdout.strip().splitlines()
        if pids:
            services[svc] = {"running": True, "pid": int(pids[0])}
    except Exception:
        pass

meta = {
    "cluster_id": cluster_id,
    "hostname": hostname,
    "collection_timestamp": timestamp,
    "duration_seconds": duration,
    "frequency_hz": frequency,
    "kernel_version": kernel,
    "cpu_model": cpu_info,
    "cpu_count": cpu_count,
    "mem_total": mem_total,
    "services": services,
}

with open(output_path, "w") as f:
    json.dump(meta, f, indent=2)
PYEOF

echo "[5/7] Capturing top snapshot..."
top -bcn1 -w 512 > "${WORK_DIR}/top_snapshot.txt" 2>/dev/null || \
    top -bn1 > "${WORK_DIR}/top_snapshot.txt" 2>/dev/null || true

echo "[6/7] Capturing ps snapshot..."
ps -eo user,pid,ppid,%cpu,%mem,stat,args --no-headers ww > "${WORK_DIR}/ps_aux.txt" 2>/dev/null || \
    ps auxww > "${WORK_DIR}/ps_aux.txt" 2>/dev/null || true

echo "[7/7] Packaging bundle..."
sudo rm -f "$PERF_BIN"

BUNDLE_PATH="${OUTPUT_DIR}/${BUNDLE_NAME}.tar.gz"
tar -czf "$BUNDLE_PATH" -C "$(dirname "$WORK_DIR")" "$(basename "$WORK_DIR")"

echo ""
echo "=== Done ==="
echo "Bundle: $BUNDLE_PATH"
echo "Size:   $(du -h "$BUNDLE_PATH" | cut -f1)"
echo ""
echo "Transfer this file to the Perf Flame Analyzer for analysis."
echo "Use the analyzer's web UI to filter by specific processes (stargate, cassandra, etc)."
