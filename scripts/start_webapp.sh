#!/bin/bash
#
# CryptoPDC Complete System Startup Script
# Starts the web interface, task queue, and optional worker nodes
#
# Usage: ./scripts/start_webapp.sh [--no-worker] [--workers N] [--port PORT] [--help]
#
# Services started:
#   - Web Interface: http://localhost:5000
#   - Task Queue: tcp://localhost:5555
#   - Results: tcp://localhost:5556
#   - Control: tcp://localhost:5557
#

set -e

# ============================================
# Configuration
# ============================================
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEBAPP_DIR="$PROJECT_ROOT/webapp"
PYTHON_DIR="$PROJECT_ROOT/python"
VENV_DIR="$PROJECT_ROOT/venv"
LOG_DIR="$PROJECT_ROOT/logs"
PID_FILE="$PROJECT_ROOT/.cryptopdc.pid"

# Default settings
FLASK_PORT=5000
FLASK_HOST="0.0.0.0"
TASK_PORT=5555
RESULT_PORT=5556
START_WORKER=true
NUM_WORKERS=1
DEBUG_MODE=false
BACKGROUND_MODE=false

# ============================================
# Colors and Output Functions
# ============================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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
        --no-worker)
            START_WORKER=false
            shift
            ;;
        --workers)
            NUM_WORKERS="$2"
            shift 2
            ;;
        --port)
            FLASK_PORT="$2"
            shift 2
            ;;
        --host)
            FLASK_HOST="$2"
            shift 2
            ;;
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --background|-d)
            BACKGROUND_MODE=true
            shift
            ;;
        --stop)
            stop_services
            exit 0
            ;;
        --status)
            check_status
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-worker         Don't start worker nodes"
            echo "  --workers N         Start N worker nodes (default: 1)"
            echo "  --port PORT         Flask web server port (default: 5000)"
            echo "  --host HOST         Flask host binding (default: 0.0.0.0)"
            echo "  --debug             Enable debug mode"
            echo "  --background, -d    Run in background (daemon mode)"
            echo "  --stop              Stop all running services"
            echo "  --status            Check status of services"
            echo "  --help, -h          Show this help message"
            echo ""
            echo "Services:"
            echo "  Web Interface:  http://localhost:$FLASK_PORT"
            echo "  Task Queue:     tcp://localhost:$TASK_PORT"
            echo "  Results:        tcp://localhost:$RESULT_PORT"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ============================================
# Utility Functions
# ============================================

# Check if a port is in use
port_in_use() {
    local port=$1
    if command -v ss &> /dev/null; then
        ss -tuln 2>/dev/null | grep -q ":$port "
    elif command -v netstat &> /dev/null; then
        netstat -tuln 2>/dev/null | grep -q ":$port "
    elif command -v lsof &> /dev/null; then
        lsof -i ":$port" &> /dev/null
    else
        return 1
    fi
}

# Kill process on port
kill_port() {
    local port=$1
    if command -v fuser &> /dev/null; then
        fuser -k "$port/tcp" 2>/dev/null || true
    elif command -v lsof &> /dev/null; then
        lsof -ti ":$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
    fi
}

# Stop all services
stop_services() {
    echo ""
    step "Stopping CryptoPDC services..."
    
    if [ -f "$PID_FILE" ]; then
        while read -r pid name; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null && success "Stopped $name (PID: $pid)"
            fi
        done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi
    
    # Kill any remaining processes on our ports
    for port in $FLASK_PORT $TASK_PORT $RESULT_PORT; do
        if port_in_use "$port"; then
            kill_port "$port"
        fi
    done
    
    success "All services stopped"
}

# Check status of services
check_status() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              CryptoPDC Service Status                      ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Check Flask
    if port_in_use "$FLASK_PORT"; then
        success "Web Interface:  http://localhost:$FLASK_PORT (RUNNING)"
    else
        error_msg "Web Interface:  http://localhost:$FLASK_PORT (STOPPED)"
    fi
    
    # Check Task Queue
    if port_in_use "$TASK_PORT"; then
        success "Task Queue:     tcp://localhost:$TASK_PORT (RUNNING)"
    else
        warning "Task Queue:     tcp://localhost:$TASK_PORT (STOPPED)"
    fi
    
    # Check Results
    if port_in_use "$RESULT_PORT"; then
        success "Results:        tcp://localhost:$RESULT_PORT (RUNNING)"
    else
        warning "Results:        tcp://localhost:$RESULT_PORT (STOPPED)"
    fi
    
    echo ""
    
    # Show PIDs if available
    if [ -f "$PID_FILE" ]; then
        echo "Running processes:"
        while read -r pid name; do
            if kill -0 "$pid" 2>/dev/null; then
                echo "  $name: PID $pid"
            fi
        done < "$PID_FILE"
    fi
}

# Save PID
save_pid() {
    local pid=$1
    local name=$2
    echo "$pid $name" >> "$PID_FILE"
}

# ============================================
# Header
# ============================================
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           CryptoPDC - Complete System Startup              ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================
# Pre-flight Checks
# ============================================
preflight_checks() {
    step "Running pre-flight checks..."
    
    # Check if ports are already in use
    if port_in_use "$FLASK_PORT"; then
        warning "Port $FLASK_PORT is already in use"
        read -p "Kill existing process? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            kill_port "$FLASK_PORT"
            sleep 1
        else
            fatal "Cannot start - port $FLASK_PORT is in use"
        fi
    fi
    
    # Clean up old PID file
    rm -f "$PID_FILE"
    
    success "Pre-flight checks passed"
}

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
        warning "Virtual environment not found at $VENV_DIR"
        warning "Using system Python - consider running ./scripts/install_requirements.sh"
    fi
    
    # Set PYTHONPATH
    export PYTHONPATH="$PYTHON_DIR:$PYTHONPATH"
    info "PYTHONPATH set to $PYTHON_DIR"
    
    # Set CUDA library path if needed
    if [ -d "/usr/local/cuda/lib64" ]; then
        export LD_LIBRARY_PATH="/usr/local/cuda/lib64:$LD_LIBRARY_PATH"
    fi
    
    # Check Python bindings
    BINDINGS_PATH="$PYTHON_DIR/cryptopdc/bindings"
    if ls "$BINDINGS_PATH"/cryptopdc_bindings*.so 1> /dev/null 2>&1; then
        success "Python bindings found"
    else
        warning "Python bindings not found!"
        echo ""
        echo "  Build the bindings first:"
        echo "    ./scripts/build.sh"
        echo "  Or:"
        echo "    ./scripts/compile_manual.sh"
        echo ""
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    echo ""
}

# ============================================
# Start Flask Web Server
# ============================================
start_flask() {
    step "Starting Flask Web Server..."
    
    cd "$WEBAPP_DIR"
    
    if [ "$DEBUG_MODE" = true ]; then
        export FLASK_DEBUG=1
        export FLASK_ENV=development
    fi
    
    # Start Flask with SocketIO
    if [ "$BACKGROUND_MODE" = true ]; then
        python3 app.py > "$LOG_DIR/flask.log" 2>&1 &
    else
        python3 app.py &
    fi
    FLASK_PID=$!
    
    # Wait for Flask to start
    sleep 2
    
    if kill -0 "$FLASK_PID" 2>/dev/null; then
        save_pid "$FLASK_PID" "flask"
        success "Flask Web Server started (PID: $FLASK_PID)"
        info "  URL: http://localhost:$FLASK_PORT"
    else
        fatal "Flask failed to start - check $LOG_DIR/flask.log"
    fi
    
    cd "$PROJECT_ROOT"
}

# ============================================
# Start Worker Node(s)
# ============================================
start_workers() {
    if [ "$START_WORKER" = false ]; then
        info "Worker nodes skipped (--no-worker)"
        return 0
    fi
    
    step "Starting $NUM_WORKERS worker node(s)..."
    
    for i in $(seq 0 $((NUM_WORKERS - 1))); do
        DEVICE_ID=$i
        
        if [ "$BACKGROUND_MODE" = true ]; then
            python3 "$PYTHON_DIR/cryptopdc/distributed/worker.py" \
                --master localhost \
                --device "$DEVICE_ID" \
                > "$LOG_DIR/worker_$i.log" 2>&1 &
        else
            python3 "$PYTHON_DIR/cryptopdc/distributed/worker.py" \
                --master localhost \
                --device "$DEVICE_ID" &
        fi
        WORKER_PID=$!
        
        sleep 1
        
        if kill -0 "$WORKER_PID" 2>/dev/null; then
            save_pid "$WORKER_PID" "worker_$i"
            success "Worker $i started (PID: $WORKER_PID, Device: $DEVICE_ID)"
        else
            warning "Worker $i failed to start"
        fi
    done
}

# ============================================
# Print Status Banner
# ============================================
print_status() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║               CryptoPDC System Ready!                      ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}Web Interface:${NC}  ${GREEN}http://localhost:$FLASK_PORT${NC}"
    echo -e "  ${CYAN}Task Queue:${NC}     ${GREEN}tcp://localhost:$TASK_PORT${NC}"
    echo -e "  ${CYAN}Results:${NC}        ${GREEN}tcp://localhost:$RESULT_PORT${NC}"
    echo ""
    
    if [ "$START_WORKER" = true ]; then
        echo "  Workers: $NUM_WORKERS active"
    else
        echo "  Workers: None (start with ./scripts/start_worker.sh)"
    fi
    
    echo ""
    
    if [ "$BACKGROUND_MODE" = true ]; then
        echo "  Running in background. Logs: $LOG_DIR/"
        echo ""
        echo "  To stop all services:"
        echo -e "    ${YELLOW}./scripts/start_webapp.sh --stop${NC}"
        echo ""
        echo "  To check status:"
        echo -e "    ${YELLOW}./scripts/start_webapp.sh --status${NC}"
    else
        echo -e "  ${YELLOW}Press Ctrl+C to stop all services${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
}

# ============================================
# Cleanup Handler
# ============================================
cleanup() {
    echo ""
    echo ""
    step "Shutting down services..."
    
    if [ -f "$PID_FILE" ]; then
        while read -r pid name; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null
                success "Stopped $name (PID: $pid)"
            fi
        done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi
    
    success "All services stopped. Goodbye!"
    exit 0
}

# ============================================
# Main Execution
# ============================================
main() {
    preflight_checks
    setup_environment
    start_flask
    start_workers
    print_status
    
    if [ "$BACKGROUND_MODE" = false ]; then
        # Set up signal handler for graceful shutdown
        trap cleanup INT TERM
        
        # Wait for all background processes
        wait
    fi
}

# Run main
main "$@"
