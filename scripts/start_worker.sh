#!/bin/bash
#
# CryptoPDC Worker Node Startup Script
# Starts a worker node that connects to a master server for distributed cracking
#
# Usage: ./scripts/start_worker.sh [--master IP] [--device N] [--help]
#

set -e

# ============================================
# Configuration
# ============================================
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_DIR="$PROJECT_ROOT/python"
VENV_DIR="$PROJECT_ROOT/venv"
LOG_DIR="$PROJECT_ROOT/logs"

# Default settings
MASTER_IP="localhost"
TASK_PORT=5555
RESULT_PORT=5556
DEVICE_ID=0
BACKGROUND_MODE=false

# ============================================
# Colors and Output Functions
# ============================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

success() { echo -e "${GREEN}[✓]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error_msg() { echo -e "${RED}[✗]${NC} $1"; }
fatal() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
step() { echo -e "${CYAN}[→]${NC} $1"; }

# ============================================
# Parse Arguments
# ============================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --master|-m)
            MASTER_IP="$2"
            shift 2
            ;;
        --device|-d)
            DEVICE_ID="$2"
            shift 2
            ;;
        --task-port)
            TASK_PORT="$2"
            shift 2
            ;;
        --result-port)
            RESULT_PORT="$2"
            shift 2
            ;;
        --background|-b)
            BACKGROUND_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --master, -m IP     Master server IP address (default: localhost)"
            echo "  --device, -d N      GPU device ID to use (default: 0)"
            echo "  --task-port PORT    Task queue port (default: 5555)"
            echo "  --result-port PORT  Result port (default: 5556)"
            echo "  --background, -b    Run in background"
            echo "  --help, -h          Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                          # Connect to localhost"
            echo "  $0 --master 192.168.1.100  # Connect to remote master"
            echo "  $0 --device 1              # Use GPU 1"
            echo "  $0 --master 192.168.1.100 --device 0 --background"
            exit 0
            ;;
        *)
            # Support legacy positional arguments: [master_ip] [device_id]
            if [[ -z "${LEGACY_MASTER:-}" ]]; then
                LEGACY_MASTER="$1"
                MASTER_IP="$1"
            elif [[ -z "${LEGACY_DEVICE:-}" ]]; then
                LEGACY_DEVICE="$1"
                DEVICE_ID="$1"
            else
                echo "Unknown option: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

# ============================================
# Header
# ============================================
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              CryptoPDC Worker Node                         ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Master:     $MASTER_IP"
echo "  Task Port:  $TASK_PORT"
echo "  Result Port: $RESULT_PORT"
echo "  GPU Device: $DEVICE_ID"
echo ""

# ============================================
# Setup Environment
# ============================================
setup_environment() {
    step "Setting up environment..."
    
    # Create log directory
    mkdir -p "$LOG_DIR"
    
    # Activate virtual environment
    if [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
        success "Virtual environment activated"
    else
        warning "Virtual environment not found"
        warning "Using system Python"
    fi
    
    # Set PYTHONPATH
    export PYTHONPATH="$PYTHON_DIR:$PYTHONPATH"
    
    # Set CUDA library path
    if [ -d "/usr/local/cuda/lib64" ]; then
        export LD_LIBRARY_PATH="/usr/local/cuda/lib64:$LD_LIBRARY_PATH"
    fi
    
    # Set CUDA device
    export CUDA_VISIBLE_DEVICES="$DEVICE_ID"
    
    # Check Python bindings
    BINDINGS_PATH="$PYTHON_DIR/cryptopdc/bindings"
    if ls "$BINDINGS_PATH"/cryptopdc_bindings*.so 1> /dev/null 2>&1; then
        success "Python bindings found"
    else
        warning "Python bindings not found - GPU functions may not work"
    fi
    
    echo ""
}

# ============================================
# Check GPU
# ============================================
check_gpu() {
    step "Checking GPU availability..."
    
    if command -v nvidia-smi &> /dev/null; then
        GPU_COUNT=$(nvidia-smi --list-gpus 2>/dev/null | wc -l)
        
        if [ "$GPU_COUNT" -gt 0 ]; then
            success "Found $GPU_COUNT GPU(s)"
            
            # Show GPU info for selected device
            if [ "$DEVICE_ID" -lt "$GPU_COUNT" ]; then
                GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader -i "$DEVICE_ID" 2>/dev/null)
                GPU_MEM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader -i "$DEVICE_ID" 2>/dev/null)
                success "Using GPU $DEVICE_ID: $GPU_NAME ($GPU_MEM)"
            else
                warning "Device $DEVICE_ID not available (only $GPU_COUNT GPUs found)"
                warning "Falling back to CPU mode"
            fi
        else
            warning "No GPUs detected - running in CPU-only mode"
        fi
    else
        warning "nvidia-smi not found - GPU status unknown"
    fi
    
    echo ""
}

# ============================================
# Test Connection to Master
# ============================================
test_connection() {
    step "Testing connection to master..."
    
    # Simple connectivity test using Python
    if python3 -c "
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
try:
    sock.connect(('$MASTER_IP', $TASK_PORT))
    sock.close()
    sys.exit(0)
except:
    sys.exit(1)
" 2>/dev/null; then
        success "Master reachable at $MASTER_IP:$TASK_PORT"
    else
        warning "Cannot reach master at $MASTER_IP:$TASK_PORT"
        warning "Make sure the master is running (./scripts/start_webapp.sh)"
        
        if [ "$MASTER_IP" != "localhost" ]; then
            echo ""
            echo "  For remote connections, ensure:"
            echo "    1. Master firewall allows ports $TASK_PORT, $RESULT_PORT"
            echo "    2. Master is binding to 0.0.0.0 (not just localhost)"
            echo ""
        fi
        
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    echo ""
}

# ============================================
# Start Worker
# ============================================
start_worker() {
    step "Starting worker process..."
    
    cd "$PROJECT_ROOT"
    
    WORKER_CMD="python3 -c \"
import sys
sys.path.insert(0, '$PYTHON_DIR')
from cryptopdc.distributed.worker import Worker

print('Initializing worker...')
print('  Master: $MASTER_IP')
print('  Task Port: $TASK_PORT')
print('  Result Port: $RESULT_PORT')
print('  Device ID: $DEVICE_ID')
print('')

worker = Worker(
    master_ip='$MASTER_IP',
    task_port=$TASK_PORT,
    result_port=$RESULT_PORT,
    device_id=$DEVICE_ID
)
print('Worker ready. Waiting for tasks...')
print('')
worker.run()
\""
    
    if [ "$BACKGROUND_MODE" = true ]; then
        eval "$WORKER_CMD" > "$LOG_DIR/worker_$DEVICE_ID.log" 2>&1 &
        WORKER_PID=$!
        success "Worker started in background (PID: $WORKER_PID)"
        info "Logs: $LOG_DIR/worker_$DEVICE_ID.log"
        info "To stop: kill $WORKER_PID"
    else
        echo ""
        echo -e "${GREEN}Worker starting...${NC}"
        echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
        echo ""
        echo "========================================"
        eval "$WORKER_CMD"
    fi
}

# ============================================
# Main Execution
# ============================================
main() {
    setup_environment
    check_gpu
    test_connection
    start_worker
}

# Run main
main "$@"
