#!/bin/bash
#
# CryptoPDC Python Requirements Installation Script
# This script creates a virtual environment and installs all Python dependencies
#
# Usage: ./scripts/install_requirements.sh [--force] [--no-venv] [--dev] [--help]
#

set -e

# ============================================
# Configuration
# ============================================
FORCE_REINSTALL=false
USE_VENV=true
INSTALL_DEV=false
VENV_NAME="venv"
PYTHON_MIN_VERSION="3.10"

# Get script and project directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_ROOT/$VENV_NAME"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force|-f)
            FORCE_REINSTALL=true
            shift
            ;;
        --no-venv)
            USE_VENV=false
            shift
            ;;
        --dev)
            INSTALL_DEV=true
            shift
            ;;
        --venv-name)
            VENV_NAME="$2"
            VENV_DIR="$PROJECT_ROOT/$VENV_NAME"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --force, -f     Force reinstall even if venv exists"
            echo "  --no-venv       Install to system Python (not recommended)"
            echo "  --dev           Install development dependencies"
            echo "  --venv-name     Custom virtual environment name (default: venv)"
            echo "  --help, -h      Show this help message"
            echo ""
            echo "This script creates a Python virtual environment and installs"
            echo "all dependencies required to run CryptoPDC."
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
# Header
# ============================================
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     CryptoPDC - Python Requirements Installation          ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================
# Check Python Version
# ============================================
check_python() {
    step "Checking Python installation..."
    
    if ! command -v python3 &> /dev/null; then
        fatal "Python3 is not installed. Please run ./scripts/prereqs.sh first."
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
    
    MIN_MAJOR=$(echo "$PYTHON_MIN_VERSION" | cut -d. -f1)
    MIN_MINOR=$(echo "$PYTHON_MIN_VERSION" | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -lt "$MIN_MAJOR" ] || ([ "$PYTHON_MAJOR" -eq "$MIN_MAJOR" ] && [ "$PYTHON_MINOR" -lt "$MIN_MINOR" ]); then
        fatal "Python $PYTHON_VERSION found, but >= $PYTHON_MIN_VERSION is required"
    fi
    
    success "Python $PYTHON_VERSION found"
    
    # Check pip
    if ! python3 -m pip --version &> /dev/null; then
        fatal "pip is not installed. Please run ./scripts/prereqs.sh first."
    fi
    success "pip is available"
    
    # Check venv module
    if [ "$USE_VENV" = true ]; then
        if ! python3 -c "import venv" &> /dev/null; then
            fatal "Python venv module not available. Install python3-venv package."
        fi
        success "venv module is available"
    fi
}

# ============================================
# Create Virtual Environment
# ============================================
create_venv() {
    if [ "$USE_VENV" = false ]; then
        warning "Skipping virtual environment creation (--no-venv)"
        return 0
    fi
    
    echo ""
    step "Setting up Python virtual environment..."
    
    if [ -d "$VENV_DIR" ]; then
        if [ "$FORCE_REINSTALL" = true ]; then
            warning "Removing existing virtual environment..."
            rm -rf "$VENV_DIR"
        else
            success "Virtual environment already exists at $VENV_DIR"
            return 0
        fi
    fi
    
    info "Creating virtual environment at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
    
    if [ ! -f "$VENV_DIR/bin/activate" ]; then
        fatal "Failed to create virtual environment"
    fi
    
    success "Virtual environment created"
}

# ============================================
# Activate Virtual Environment
# ============================================
activate_venv() {
    if [ "$USE_VENV" = false ]; then
        return 0
    fi
    
    step "Activating virtual environment..."
    
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    
    if [ -z "$VIRTUAL_ENV" ]; then
        fatal "Failed to activate virtual environment"
    fi
    
    success "Virtual environment activated"
    info "Python: $(which python3)"
}

# ============================================
# Upgrade pip
# ============================================
upgrade_pip() {
    echo ""
    step "Upgrading pip, setuptools, and wheel..."
    
    python3 -m pip install --upgrade pip setuptools wheel --quiet
    
    PIP_VERSION=$(python3 -m pip --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
    success "pip upgraded to $PIP_VERSION"
}

# ============================================
# Install Requirements
# ============================================
install_requirements() {
    echo ""
    step "Installing Python dependencies..."
    
    REQUIREMENTS_FILE="$PROJECT_ROOT/requirements.txt"
    
    if [ ! -f "$REQUIREMENTS_FILE" ]; then
        fatal "requirements.txt not found at $REQUIREMENTS_FILE"
    fi
    
    # Install main requirements
    info "Installing from requirements.txt..."
    python3 -m pip install -r "$REQUIREMENTS_FILE" --quiet
    
    success "Main dependencies installed"
    
    # Install pybind11 (required for building C++ bindings)
    step "Installing pybind11 for C++ bindings..."
    python3 -m pip install "pybind11[global]>=2.11.0" --quiet
    success "pybind11 installed"
    
    # Install development dependencies if requested
    if [ "$INSTALL_DEV" = true ]; then
        echo ""
        step "Installing development dependencies..."
        python3 -m pip install \
            pytest>=7.4.0 \
            pytest-cov>=4.1.0 \
            pytest-asyncio>=0.21.0 \
            black>=23.0.0 \
            flake8>=6.1.0 \
            mypy>=1.5.0 \
            isort>=5.12.0 \
            --quiet
        success "Development dependencies installed"
    fi
}

# ============================================
# Verify Installation
# ============================================
verify_installation() {
    echo ""
    step "Verifying installation..."
    
    ERRORS=0
    
    # Core packages verification
    PACKAGES=(
        "flask:Flask"
        "flask_socketio:Flask-SocketIO"
        "flask_cors:Flask-CORS"
        "zmq:pyzmq"
        "pybind11:pybind11"
        "numpy:numpy"
        "jinja2:Jinja2"
        "websockets:websockets"
    )
    
    for pkg_check in "${PACKAGES[@]}"; do
        MODULE="${pkg_check%%:*}"
        NAME="${pkg_check##*:}"
        
        if python3 -c "import $MODULE" 2>/dev/null; then
            VERSION=$(python3 -c "import $MODULE; print(getattr($MODULE, '__version__', 'unknown'))" 2>/dev/null || echo "installed")
            success "$NAME: $VERSION"
        else
            error_msg "$NAME: NOT INSTALLED"
            ERRORS=$((ERRORS + 1))
        fi
    done
    
    echo ""
    if [ $ERRORS -eq 0 ]; then
        success "All packages verified successfully!"
        return 0
    else
        error_msg "$ERRORS package(s) failed verification"
        return 1
    fi
}

# ============================================
# Create Activation Script Helper
# ============================================
create_activation_helper() {
    if [ "$USE_VENV" = false ]; then
        return 0
    fi
    
    ACTIVATE_HELPER="$PROJECT_ROOT/activate.sh"
    
    cat > "$ACTIVATE_HELPER" << 'EOF'
#!/bin/bash
# CryptoPDC Environment Activation Helper
# Source this file to activate the environment: source activate.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

if [ -f "$VENV_DIR/bin/activate" ]; then
    source "$VENV_DIR/bin/activate"
    export PYTHONPATH="$SCRIPT_DIR/python:$PYTHONPATH"
    echo "CryptoPDC environment activated"
    echo "  Python: $(which python3)"
    echo "  PYTHONPATH: $PYTHONPATH"
else
    echo "Virtual environment not found at $VENV_DIR"
    echo "Run ./scripts/install_requirements.sh first"
fi
EOF
    
    chmod +x "$ACTIVATE_HELPER"
    success "Created activation helper: $ACTIVATE_HELPER"
}

# ============================================
# Print Summary
# ============================================
print_summary() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                Installation Complete!                      ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ "$USE_VENV" = true ]; then
        echo "  Virtual environment: $VENV_DIR"
        echo ""
        echo "  To activate the environment manually:"
        echo -e "    ${YELLOW}source $VENV_DIR/bin/activate${NC}"
        echo ""
        echo "  Or use the helper script:"
        echo -e "    ${YELLOW}source $PROJECT_ROOT/activate.sh${NC}"
    fi
    
    echo ""
    echo "  Next steps:"
    echo -e "    1. Build C++/CUDA: ${YELLOW}./scripts/build.sh${NC}"
    echo -e "    2. Start webapp:   ${YELLOW}./scripts/start_webapp.sh${NC}"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

# ============================================
# Main Execution
# ============================================
main() {
    cd "$PROJECT_ROOT"
    
    check_python
    create_venv
    activate_venv
    upgrade_pip
    install_requirements
    
    if verify_installation; then
        create_activation_helper
        print_summary
    else
        fatal "Installation verification failed. Please check the errors above."
    fi
}

# Run main
main "$@"
