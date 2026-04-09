#!/bin/bash
set -euo pipefail

#
# Deploy FlamePerf Linux Analyzer to Rocky Linux 9 VM
#
# Usage: ./deploy.sh [--target user@host] [--rebuild]
#
# Prerequisites:
#   - Passwordless SSH to the target
#   - /perfanal filesystem exists on the target
#

TARGET="${1:-root@10.69.2.186}"
REMOTE_BASE="/perfanal/perf-analyzer"
REMOTE_COLLECTOR="/perfanal/cvm-collector"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "============================================"
echo " FlamePerf Linux Analyzer - Deployment"
echo "============================================"
echo " Target : $TARGET"
echo " App dir: $REMOTE_BASE"
echo " Source : $SCRIPT_DIR"
echo ""

run_remote() {
    ssh -o ConnectTimeout=10 "$TARGET" "$@"
}

# --- Step 1: Test SSH ---
echo "[1/9] Testing SSH connectivity..."
run_remote "echo 'SSH OK - $(hostname)'"

# --- Step 2: Install podman if needed ---
echo "[2/9] Ensuring podman is installed..."
run_remote "command -v podman >/dev/null 2>&1 && echo 'podman already installed' || { echo 'Installing podman...'; dnf install -y podman; }"

# --- Step 3: Create directory structure ---
echo "[3/9] Creating directory structure..."
run_remote "mkdir -p ${REMOTE_BASE}/{templates,static,data} ${REMOTE_COLLECTOR}"

# --- Step 4: Copy all files ---
echo "[4/9] Copying application files..."

scp -q "${SCRIPT_DIR}/analyzer/Containerfile"      "${TARGET}:${REMOTE_BASE}/"
scp -q "${SCRIPT_DIR}/analyzer/requirements.txt"   "${TARGET}:${REMOTE_BASE}/"
scp -q "${SCRIPT_DIR}/analyzer/app.py"             "${TARGET}:${REMOTE_BASE}/"
scp -q "${SCRIPT_DIR}/analyzer/parser.py"          "${TARGET}:${REMOTE_BASE}/"
scp -q "${SCRIPT_DIR}/analyzer/diagnostics.py"     "${TARGET}:${REMOTE_BASE}/"
scp -q "${SCRIPT_DIR}/analyzer/models.py"          "${TARGET}:${REMOTE_BASE}/"
scp -q "${SCRIPT_DIR}/analyzer/static/style.css"   "${TARGET}:${REMOTE_BASE}/static/"
scp -q "${SCRIPT_DIR}/analyzer/static/tux.png"    "${TARGET}:${REMOTE_BASE}/static/"
scp -q "${SCRIPT_DIR}/analyzer/templates/base.html"       "${TARGET}:${REMOTE_BASE}/templates/"
scp -q "${SCRIPT_DIR}/analyzer/templates/dashboard.html"   "${TARGET}:${REMOTE_BASE}/templates/"
scp -q "${SCRIPT_DIR}/analyzer/templates/upload.html"      "${TARGET}:${REMOTE_BASE}/templates/"
scp -q "${SCRIPT_DIR}/analyzer/templates/analysis.html"    "${TARGET}:${REMOTE_BASE}/templates/"
scp -q "${SCRIPT_DIR}/cvm-collector/perf-collect.sh"       "${TARGET}:${REMOTE_COLLECTOR}/"
scp -q "${SCRIPT_DIR}/cvm-collector/perf-collect.sh"       "${TARGET}:${REMOTE_BASE}/perf-collect.sh"

echo "  Files deployed:"
run_remote "find ${REMOTE_BASE} ${REMOTE_COLLECTOR} -type f | sort"

# --- Step 5: Stop existing container ---
echo ""
echo "[5/9] Stopping existing container (if any)..."
run_remote "podman stop perf-analyzer 2>/dev/null || true; podman rm perf-analyzer 2>/dev/null || true"

# --- Step 6: Clean old images to force full rebuild ---
echo "[6/9] Cleaning old container images..."
run_remote "podman rmi perf-analyzer 2>/dev/null || true; podman image prune -f 2>/dev/null || true"

# --- Step 7: Build container ---
echo "[7/9] Building container image (this may take a minute on first run)..."
run_remote "cd ${REMOTE_BASE} && podman build --no-cache -t perf-analyzer -f Containerfile ."

# --- Step 8: Run container ---
echo "[8/9] Starting container..."
run_remote "podman run -d \
    --name perf-analyzer \
    --restart always \
    -p 8080:8080 \
    -v ${REMOTE_BASE}/data:/app/data:Z \
    perf-analyzer"

echo "  Waiting for container to start..."
sleep 3

CONTAINER_STATUS=$(run_remote "podman inspect --format '{{.State.Status}}' perf-analyzer 2>/dev/null || echo 'not found'")
if [[ "$CONTAINER_STATUS" == "running" ]]; then
    echo "  Container is running."
    run_remote "podman ps --filter name=perf-analyzer --format 'table {{.ID}}\t{{.Status}}\t{{.Ports}}'"
else
    echo "  WARNING: Container status is '${CONTAINER_STATUS}'. Checking logs..."
    run_remote "podman logs --tail 30 perf-analyzer" || true
fi

# --- Step 9: Configure firewall + systemd ---
echo ""
echo "[9/9] Configuring firewall and systemd..."

run_remote "firewall-cmd --query-port=8080/tcp >/dev/null 2>&1 && echo '  Port 8080 already open' || { firewall-cmd --add-port=8080/tcp --permanent && firewall-cmd --reload && echo '  Port 8080 opened'; }"

run_remote "cat > /etc/systemd/system/perf-analyzer.service << 'UNIT'
[Unit]
Description=FlamePerf Linux Analyzer Container
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=5
ExecStartPre=-/usr/bin/podman stop perf-analyzer
ExecStartPre=-/usr/bin/podman rm perf-analyzer
ExecStart=/usr/bin/podman run --name perf-analyzer \
    -p 8080:8080 \
    -v /perfanal/perf-analyzer/data:/app/data:Z \
    perf-analyzer
ExecStop=/usr/bin/podman stop perf-analyzer

[Install]
WantedBy=multi-user.target
UNIT"

run_remote "systemctl daemon-reload && systemctl enable perf-analyzer.service 2>/dev/null"
echo "  systemd service enabled."

echo ""
echo "============================================"
echo " Deployment complete!"
echo ""
echo " Web UI:  http://10.69.2.186:8080"
echo ""
echo " Collector script on analyzer VM:"
echo "   ${TARGET}:${REMOTE_COLLECTOR}/perf-collect.sh"
echo ""
echo " To grab the collector for a customer CVM:"
echo "   scp ${TARGET}:${REMOTE_COLLECTOR}/perf-collect.sh ."
echo ""
echo " Data volume (persists across rebuilds):"
echo "   ${REMOTE_BASE}/data/"
echo ""
echo " Management:"
echo "   ssh ${TARGET} podman logs -f perf-analyzer"
echo "   ssh ${TARGET} podman restart perf-analyzer"
echo "   ssh ${TARGET} systemctl status perf-analyzer"
echo "============================================"
