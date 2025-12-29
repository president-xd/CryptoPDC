#!/bin/bash
#
# CryptoPDC Prerequisites Installation Script
# This script installs all required dependencies for building and running CryptoPDC
#

set -e

echo "=============================================="
echo "  CryptoPDC Prerequisites Installation"
echo "=============================================="
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "[ERROR] Cannot detect OS"
    exit 1
fi

echo "[INFO] Detected OS: $OS $VERSION"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success() { echo -e "${GREEN}[OK]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install system packages based on OS
install_system_packages() {
    echo ""
    echo "=== Installing System Packages ==="
    
    case $OS in
        ubuntu|debian)
            echo "[INFO] Using apt package manager"
            sudo apt-get update
            
            # Essential build tools
            sudo apt-get install -y \
                build-essential \
                cmake \
                git \
                pkg-config \
                wget \
                curl
            
            # Python development
            sudo apt-get install -y \
                python3 \
                python3-pip \
                python3-dev \
                python3-venv
            
            # Optional: Google Test for C++ testing
            sudo apt-get install -y \
                libgtest-dev
            
            success "System packages installed"
            ;;
            
        fedora|rhel|centos)
            echo "[INFO] Using dnf/yum package manager"
            sudo dnf install -y \
                gcc-c++ \
                cmake \
                git \
                pkg-config \
                wget \
                curl \
                python3 \
                python3-pip \
                python3-devel \
                gtest-devel
            
            success "System packages installed"
            ;;
            
        arch|manjaro)
            echo "[INFO] Using pacman package manager"
            sudo pacman -Sy --noconfirm \
                base-devel \
                cmake \
                git \
                pkg-config \
                wget \
                curl \
                python \
                python-pip \
                gtest
            
            success "System packages installed"
            ;;
            
        *)
            warning "Unsupported OS: $OS"
            echo "Please manually install:"
            echo "  - C++ compiler (g++ or clang)"
            echo "  - CMake >= 3.18"
            echo "  - Python >= 3.10"
            echo "  - pip"
            echo "  - Google Test (optional)"
            ;;
    esac
}

# Check and install CUDA
install_cuda() {
    echo ""
    echo "=== Checking CUDA Installation ==="
    
    if command_exists nvcc; then
        CUDA_VERSION=$(nvcc --version | grep "release" | sed 's/.*release \([0-9.]*\).*/\1/')
        success "CUDA found: version $CUDA_VERSION"
        
        # Check if nvidia-smi works
        if command_exists nvidia-smi; then
            success "NVIDIA driver working"
            nvidia-smi --query-gpu=name,driver_version --format=csv,noheader
        else
            warning "nvidia-smi not found. GPU may not be accessible."
        fi
    else
        warning "CUDA not found!"
        echo ""
        echo "To install CUDA:"
        echo ""
        case $OS in
            ubuntu|debian)
                echo "Option 1: Install from NVIDIA repository (recommended)"
                echo "  wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb"
                echo "  sudo dpkg -i cuda-keyring_1.1-1_all.deb"
                echo "  sudo apt-get update"
                echo "  sudo apt-get install cuda-toolkit-12-0"
                echo ""
                echo "Option 2: Install from Ubuntu repository"
                echo "  sudo apt-get install nvidia-cuda-toolkit"
                ;;
            fedora|rhel|centos)
                echo "  sudo dnf config-manager --add-repo https://developer.download.nvidia.com/compute/cuda/repos/fedora37/x86_64/cuda-fedora37.repo"
                echo "  sudo dnf install cuda-toolkit-12-0"
                ;;
            arch|manjaro)
                echo "  sudo pacman -S cuda"
                ;;
            *)
                echo "  Visit: https://developer.nvidia.com/cuda-downloads"
                ;;
        esac
        echo ""
        echo "After installing CUDA, add to your ~/.bashrc:"
        echo '  export PATH=/usr/local/cuda/bin:$PATH'
        echo '  export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH'
        echo ""
        
        read -p "Continue without CUDA? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Install Python packages
install_python_packages() {
    echo ""
    echo "=== Installing Python Packages ==="
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    VENV_DIR="$PROJECT_DIR/venv"
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "$VENV_DIR" ]; then
        echo "[INFO] Creating Python virtual environment..."
        python3 -m venv "$VENV_DIR"
        success "Virtual environment created at $VENV_DIR"
    else
        success "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    echo "[INFO] Upgrading pip..."
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "$PROJECT_DIR/requirements.txt" ]; then
        echo "[INFO] Installing Python packages from requirements.txt..."
        pip install -r "$PROJECT_DIR/requirements.txt"
        success "Python packages installed"
    else
        warning "requirements.txt not found, installing core packages..."
        pip install \
            flask \
            flask-socketio \
            flask-cors \
            pyzmq \
            pybind11 \
            numpy \
            pytest
        success "Core Python packages installed"
    fi
    
    # Deactivate
    deactivate
}

# Verify installation
verify_installation() {
    echo ""
    echo "=== Verifying Installation ==="
    
    ERRORS=0
    
    # Check cmake
    if command_exists cmake; then
        CMAKE_VERSION=$(cmake --version | head -n1)
        success "CMake: $CMAKE_VERSION"
    else
        error "CMake not found"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Check g++
    if command_exists g++; then
        GCC_VERSION=$(g++ --version | head -n1)
        success "G++: $GCC_VERSION"
    else
        error "G++ not found"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Check python
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version)
        success "Python: $PYTHON_VERSION"
    else
        error "Python3 not found"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Check pip
    if command_exists pip3; then
        PIP_VERSION=$(pip3 --version)
        success "Pip: $PIP_VERSION"
    else
        error "Pip3 not found"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Check CUDA (optional)
    if command_exists nvcc; then
        NVCC_VERSION=$(nvcc --version | grep "release" | sed 's/.*release //')
        success "CUDA: $NVCC_VERSION"
    else
        warning "CUDA: Not installed (GPU acceleration unavailable)"
    fi
    
    echo ""
    if [ $ERRORS -eq 0 ]; then
        success "All prerequisites are installed!"
    else
        error "$ERRORS required packages are missing"
    fi
}

# Print next steps
print_next_steps() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    
    echo ""
    echo "=============================================="
    echo "  Next Steps"
    echo "=============================================="
    echo ""
    echo "1. Build the project:"
    echo "   cd $PROJECT_DIR"
    echo "   ./scripts/build.sh"
    echo ""
    echo "2. Start the web application:"
    echo "   ./scripts/start_webapp.sh"
    echo ""
    echo "3. Open in browser:"
    echo "   http://localhost:5000"
    echo ""
    echo "=============================================="
}

# Main execution
main() {
    # Check if running as root (not recommended for pip)
    if [ "$EUID" -eq 0 ]; then
        warning "Running as root is not recommended for Python package installation"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    install_system_packages
    install_cuda
    install_python_packages
    verify_installation
    print_next_steps
}

# Run main
main "$@"
