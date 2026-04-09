#!/bin/bash
#
# Author: sergei.ivanov@nutanix.com
#
# Collect perf profiling data on a Nutanix CVM or FSVM and package it for analysis.
# Also works on regular Linux machines.
#
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

# ── Platform detection ──

version_ge() {
    # Returns 0 (true) if $1 >= $2, using sort -V for version comparison
    printf '%s\n%s' "$2" "$1" | sort -V -C
}

HAS_ZFS=false
if command -v zfs &>/dev/null; then
    HAS_ZFS=true
fi

HAS_PERF=false
if command -v perf &>/dev/null; then
    HAS_PERF=true
fi

HOSTNAME_UPPER=$(echo "$HOSTNAME_SHORT" | tr '[:lower:]' '[:upper:]')

MACHINE_TYPE="Linux"
if [[ -f /etc/nutanix/pc-marker || -f /etc/nutanix/pcvm-version ]]; then
    MACHINE_TYPE="PCVM"
elif [[ "$HOSTNAME_UPPER" == *FSVM* ]]; then
    MACHINE_TYPE="FSVM"
elif [[ "$HOSTNAME_UPPER" == *CVM* ]]; then
    if [[ "$HAS_ZFS" == "false" ]]; then
        MACHINE_TYPE="CVM"
    else
        MACHINE_TYPE="FSVM"
    fi
elif [[ -d /etc/nutanix ]]; then
    if [[ "$HAS_ZFS" == "true" ]]; then
        MACHINE_TYPE="FSVM"
    else
        MACHINE_TYPE="CVM"
    fi
fi

# ── Perf availability verification ──

if [[ "$HAS_PERF" == "false" ]]; then
    case "$MACHINE_TYPE" in
        CVM|PCVM)
            echo "ERROR: perf is expected on a CVM but was not found."
            echo "       This is unexpected. Investigate the system or install the perf package."
            exit 1
            ;;
        Linux)
            echo "ERROR: perf is not installed on this machine."
            echo "       Install the perf package (e.g. 'yum install perf' or 'apt install linux-tools-\$(uname -r)') and re-run."
            exit 1
            ;;
        FSVM)
            AFS_VER=""
            AFS_VER_RAW=$(afs version 2>/dev/null || true)
            if [[ -n "$AFS_VER_RAW" ]]; then
                AFS_VER=$(echo "$AFS_VER_RAW" | grep -oP '\d+\.\d+(\.\d+)?' | head -1)
            fi

            if [[ -z "$AFS_VER" ]]; then
                echo "ERROR: perf is not installed and could not determine AFS version."
                echo "       Install the perf package manually and re-run."
                exit 1
            fi

            echo "Detected FSVM with AFS version $AFS_VER (perf not installed)"

            if ! version_ge "$AFS_VER" "5.2.1"; then
                echo "ERROR: AFS version $AFS_VER is older than 5.2.1."
                echo "       Automated perf installation is not available for this version."
                echo "       Obtain and install the perf RPM manually, then re-run."
                exit 1
            fi

            if ! sudo test -f /root/sretools/sreinstall.sh; then
                echo "ERROR: perf is not installed and /root/sretools/sreinstall.sh was not found."
                echo "       Install the perf package manually and re-run."
                exit 1
            fi

            echo ""
            read -r -p "perf is not installed. Install it via /root/sretools/sreinstall.sh? [y/N] " REPLY
            if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
                echo "Aborted by user."
                exit 1
            fi

            echo "Running sreinstall.sh..."
            sudo bash /root/sretools/sreinstall.sh

            if ! command -v perf &>/dev/null; then
                echo "ERROR: perf is still not available after running sreinstall.sh."
                echo "       Install the perf package manually and re-run."
                exit 1
            fi
            HAS_PERF=true
            echo "perf installed successfully."
            ;;
    esac
fi

# ── Set up working directory ──

TIMESTAMP=$(date +'%Y-%m-%d-%H-%M-%S')
BUNDLE_NAME="perf-bundle-${CLUSTER_ID}-${HOSTNAME_SHORT}-${TIMESTAMP}"
WORK_DIR="${OUTPUT_DIR}/${BUNDLE_NAME}"
mkdir -p "$WORK_DIR"

trap 'sudo rm -rf "$WORK_DIR"' EXIT

echo "=== Perf Collector ==="
echo "Cluster ID : $CLUSTER_ID"
echo "Hostname   : $HOSTNAME_SHORT"
echo "Machine    : $MACHINE_TYPE"
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

echo "[1/8] Starting iostat sampling (1s intervals)..."
iostat -dxy 1 > "${WORK_DIR}/iostat_data.txt" 2>/dev/null &
IOSTAT_PID=$!
echo "       iostat PID: $IOSTAT_PID"

IOTOP_TID_PID=""
IOTOP_PID_PID=""
if command -v iotop &>/dev/null; then
    echo "[2/8] Starting iotop sampling (1s intervals, ${DURATION} iterations)..."
    sudo iotop -b -o -d 1 -n "$DURATION" > "${WORK_DIR}/iotop_data.txt" 2>/dev/null &
    IOTOP_TID_PID=$!
    sudo iotop -b -o -P -d 1 -n "$DURATION" > "${WORK_DIR}/iotop_pid_data.txt" 2>/dev/null &
    IOTOP_PID_PID=$!
    echo "       iotop by-TID PID: $IOTOP_TID_PID, by-PID PID: $IOTOP_PID_PID"
else
    echo "[2/8] iotop not installed, skipping process I/O collection"
fi

echo "[3/8] Recording perf data (${DURATION}s, event=${EVENT})..."

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

if [[ -n "$IOTOP_TID_PID" ]]; then
    kill "$IOTOP_TID_PID" 2>/dev/null || true
    kill "$IOTOP_PID_PID" 2>/dev/null || true
    wait "$IOTOP_TID_PID" 2>/dev/null || true
    wait "$IOTOP_PID_PID" 2>/dev/null || true
    echo "       iotop ticks collected: $(grep -c '^Total DISK READ' "${WORK_DIR}/iotop_data.txt" 2>/dev/null || echo 0)"
fi

echo "[4/8] Generating perf script output..."
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

echo "[5/8] Collecting system metadata..."

python3 - "$CLUSTER_ID" "$HOSTNAME_SHORT" "$TIMESTAMP" "$DURATION" "$FREQUENCY" "$MACHINE_TYPE" "${WORK_DIR}/metadata.json" <<'PYEOF'
import json, platform, os, sys, subprocess

cluster_id    = sys.argv[1]
hostname      = sys.argv[2]
timestamp     = sys.argv[3]
duration      = int(sys.argv[4])
frequency     = int(sys.argv[5])
machine_type  = sys.argv[6]
output_path   = sys.argv[7]

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
    "machine_type": machine_type,
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

echo "[6/8] Capturing top snapshot..."
top -bcn1 -w 512 > "${WORK_DIR}/top_snapshot.txt" 2>/dev/null || \
    top -bn1 > "${WORK_DIR}/top_snapshot.txt" 2>/dev/null || true

echo "[7/8] Capturing ps snapshot..."
ps -eo user,pid,ppid,%cpu,%mem,stat,args --no-headers ww > "${WORK_DIR}/ps_aux.txt" 2>/dev/null || \
    ps auxww > "${WORK_DIR}/ps_aux.txt" 2>/dev/null || true

echo "[8/8] Packaging bundle..."
sudo rm -f "$PERF_BIN"

BUNDLE_PATH="${OUTPUT_DIR}/${BUNDLE_NAME}.tar.gz"
tar -czf "$BUNDLE_PATH" -C "$(dirname "$WORK_DIR")" "$(basename "$WORK_DIR")"

echo ""
echo "=== Done ==="
echo "Bundle: $BUNDLE_PATH"
echo "Size:   $(du -h "$BUNDLE_PATH" | cut -f1)"
echo ""
echo "Transfer this file to the FlamePerf Linux Analyzer for analysis."
echo "Use the analyzer's web UI to filter by specific processes (stargate, cassandra, etc)."
