#!/bin/bash
set -e

echo "=========================================="
echo "  CryptoPDC - Complete System Startup"
echo "=========================================="
echo ""

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Change to project root
cd "$PROJECT_ROOT"

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
    echo "✓ Virtual environment activated"
fi

# Set PYTHONPATH
export PYTHONPATH="$PROJECT_ROOT/python"
echo "✓ PYTHONPATH set to $PYTHONPATH"

# Check if worker should be started
START_WORKER=${1:-"yes"}

# Start Flask Web Interface
echo ""
echo "Starting Flask Web Interface..."
cd "$PROJECT_ROOT/webapp"
python3 app.py &
FLASK_PID=$!
echo "✓ Flask started (PID: $FLASK_PID)"

# Wait for Flask to initialize
sleep 3

# Start Worker if requested
if [ "$START_WORKER" = "yes" ]; then
    echo ""
    echo "Starting Worker Node..."
    cd "$PROJECT_ROOT"
    python3 python/cryptopdc/distributed/worker.py &
    WORKER_PID=$!
    echo "✓ Worker started (PID: $WORKER_PID)"
fi

echo ""
echo "=========================================="
echo "  System Ready!"
echo "=========================================="
echo ""
echo "🌐 Web Interface: http://localhost:5000"
echo "📡 Task Queue: tcp://localhost:5555"
echo "📥 Results: tcp://localhost:5556"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for interrupt
trap "echo ''; echo 'Stopping services...'; kill $FLASK_PID 2>/dev/null; [ -n \"\$WORKER_PID\" ] && kill \$WORKER_PID 2>/dev/null; exit 0" INT

wait
