#!/bin/bash
# CryptoPDC Worker Startup Script
# Usage: ./scripts/start_worker.sh [master_ip] [device_id]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

MASTER_IP=${1:-"localhost"}
DEVICE_ID=${2:-0}

cd "$PROJECT_ROOT"

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
fi

export PYTHONPATH="$PROJECT_ROOT/python"

echo "=========================================="
echo "  CryptoPDC Worker Node"
echo "=========================================="
echo ""
echo "Master IP: $MASTER_IP"
echo "GPU Device: $DEVICE_ID"
echo ""

python3 -c "
import sys
sys.path.insert(0, '$PROJECT_ROOT/python')
from cryptopdc.distributed.worker import Worker

worker = Worker(
    master_ip='$MASTER_IP',
    task_port=5555,
    result_port=5556,
    device_id=$DEVICE_ID
)
worker.run()
"
