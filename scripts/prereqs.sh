#!/bin/bash
#
# CryptoPDC Prerequisites Installation Script
# This script installs all required system dependencies for building and running CryptoPDC
#
# Usage: ./scripts/prereqs.sh [--skip-cuda] [--skip-python] [--help]
#

set -e

# ============================================
# Configuration
# ============================================
SKIP_CUDA=false
SKIP_PYTHON=false
MIN_CMAKE_VERSION="3.18"
MIN_GCC_VERSION="9"
MIN_PYTHON_VERSION="3.10"
MIN_CUDA_VERSION="11.5"

# Get script and project directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-cuda)
            SKIP_CUDA=true
            shift
            ;;
        --skip-python)
            SKIP_PYTHON=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-cuda     Skip CUDA installation check"
            echo "  --skip-python   Skip Python virtual environment setup"
            echo "  --help, -h      Show this help message"
            echo ""
            echo "This script installs system prerequisites for CryptoPDC."
            echo "For Python dependencies, use ./scripts/install_requirements.sh"
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
echo -e "${CYAN}║       CryptoPDC - Prerequisites Installation Script        ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  This script will install:"
echo "    • Build tools (cmake >= $MIN_CMAKE_VERSION, g++ >= $MIN_GCC_VERSION, make)"
echo "    • Python >= $MIN_PYTHON_VERSION with pip and venv"
echo "    • CUDA toolkit >= $MIN_CUDA_VERSION (for GPU acceleration)"
echo "    • OpenMP for CPU parallelization"
echo ""

# ============================================
# OS Detection
# ============================================
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    fatal "Cannot detect OS. This script supports Ubuntu, Debian, Fedora, CentOS, Arch, and Manjaro."
fi

info "Detected OS: $OS $VERSION"
echo ""

# ============================================
# Utility Functions
# ============================================
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Compare versions: returns 0 if $1 >= $2
version_gte() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# ============================================
# Install System Packages
# ============================================
install_system_packages() {
    echo ""
    echo -e "${CYAN}=== Step 1: Installing System Packages ===${NC}"
    
    case $OS in
        ubuntu|debian)
            info "Using apt package manager"
            sudo apt-get update
            
            step "Installing build tools..."
            sudo apt-get install -y \
                build-essential \
                cmake \
                make \
                git \
                pkg-config \
                wget \
                curl
            
            step "Installing OpenMP..."
            sudo apt-get install -y libomp-dev
            
            step "Installing Python development packages..."
            sudo apt-get install -y \
                python3 \
                python3-pip \
                python3-dev \
                python3-venv
            
            step "Installing optional packages..."
            sudo apt-get install -y libgtest-dev || warning "Google Test not installed (optional)"
            sudo apt-get install -y htop || true
            
            success "System packages installed"
            ;;
            
        fedora|rhel|centos)
            info "Using dnf package manager"
            
            step "Installing build tools..."
            sudo dnf install -y \
                gcc-c++ \
                cmake \
                make \
                git \
                pkg-config \
                wget \
                curl
            
            step "Installing OpenMP..."
            sudo dnf install -y libomp-devel || sudo dnf install -y libgomp-devel
            
            step "Installing Python development packages..."
            sudo dnf install -y \
                python3 \
                python3-pip \
                python3-devel
            
            step "Installing optional packages..."
            sudo dnf install -y gtest-devel || warning "Google Test not installed (optional)"
            
            success "System packages installed"
            ;;
            
        arch|manjaro)
            info "Using pacman package manager"
            
            step "Installing packages..."
            sudo pacman -Sy --noconfirm \
                base-devel \
                cmake \
                git \
                pkg-config \
                wget \
                curl \
                openmp \
                python \
                python-pip \
                gtest
            
            success "System packages installed"
            ;;
            
        *)
            warning "Unsupported OS: $OS"
            echo ""
            echo "Please manually install the following packages:"
            echo "  • C++ compiler: g++ >= $MIN_GCC_VERSION or clang >= 10"
            echo "  • CMake >= $MIN_CMAKE_VERSION"
            echo "  • Python >= $MIN_PYTHON_VERSION with pip and venv"
            echo "  • OpenMP development libraries"
            echo "  • Google Test (optional, for testing)"
            echo ""
            read -p "Continue anyway? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            ;;
    esac
}

# ============================================
# Check and Install CUDA
# ============================================
check_cuda() {
    echo ""
    echo -e "${CYAN}=== Step 2: Checking CUDA Installation ===${NC}"
    
    if [ "$SKIP_CUDA" = true ]; then
        warning "CUDA check skipped (--skip-cuda flag)"
        return 0
    fi
    
    if command_exists nvcc; then
        CUDA_VERSION=$(nvcc --version | grep "release" | sed 's/.*release \([0-9.]*\).*/\1/')
        success "CUDA found: version $CUDA_VERSION"
        
        # Check CUDA version
        CUDA_MAJOR=$(echo "$CUDA_VERSION" | cut -d. -f1)
        if [ "$CUDA_MAJOR" -lt 11 ]; then
            warning "CUDA version $CUDA_VERSION is older than recommended ($MIN_CUDA_VERSION+)"
        fi
        
        # Check if nvidia-smi works
        if command_exists nvidia-smi; then
            success "NVIDIA driver working"
            echo ""
            nvidia-smi --query-gpu=index,name,driver_version,memory.total --format=csv,noheader
            echo ""
        else
            warning "nvidia-smi not found. GPU may not be accessible."
        fi
        
        # Check CUDA paths
        if [ -z "$CUDA_HOME" ] && [ -d "/usr/local/cuda" ]; then
            warning "CUDA_HOME not set. Consider adding to ~/.bashrc:"
            echo '  export CUDA_HOME=/usr/local/cuda'
            echo '  export PATH=$CUDA_HOME/bin:$PATH'
            echo '  export LD_LIBRARY_PATH=$CUDA_HOME/lib64:$LD_LIBRARY_PATH'
        fi
    else
        warning "CUDA not found!"
        echo ""
        echo "To install CUDA, follow these steps:"
        echo ""
        
        case $OS in
            ubuntu|debian)
                echo "Option 1: Install from NVIDIA repository (recommended)"
                echo "  wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb"
                echo "  sudo dpkg -i cuda-keyring_1.1-1_all.deb"
                echo "  sudo apt-get update"
                echo "  sudo apt-get install cuda-toolkit-12-4"
                echo ""
                echo "Option 2: Install from Ubuntu repository (easier but older)"
                echo "  sudo apt-get install nvidia-cuda-toolkit"
                ;;
            fedora|rhel|centos)
                echo "  sudo dnf config-manager --add-repo https://developer.download.nvidia.com/compute/cuda/repos/rhel9/x86_64/cuda-rhel9.repo"
                echo "  sudo dnf install cuda-toolkit-12-4"
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
        echo '  export CUDA_HOME=/usr/local/cuda'
        echo '  export PATH=$CUDA_HOME/bin:$PATH'
        echo '  export LD_LIBRARY_PATH=$CUDA_HOME/lib64:$LD_LIBRARY_PATH'
        echo ""
        
        warning "CryptoPDC will work without CUDA but GPU acceleration will be disabled."
        read -p "Continue without CUDA? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# ============================================
# Verify Installation
# ============================================
verify_installation() {
    echo ""
    echo -e "${CYAN}=== Step 3: Verifying Installation ===${NC}"
    
    ERRORS=0
    WARNINGS=0
    
    # Check cmake
    if command_exists cmake; then
        CMAKE_VERSION=$(cmake --version | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        CMAKE_MAJOR_MINOR=$(echo "$CMAKE_VERSION" | cut -d. -f1-2)
        if version_gte "$CMAKE_MAJOR_MINOR" "$MIN_CMAKE_VERSION"; then
            success "CMake: $CMAKE_VERSION (>= $MIN_CMAKE_VERSION required)"
        else
            error_msg "CMake: $CMAKE_VERSION (< $MIN_CMAKE_VERSION required)"
            ERRORS=$((ERRORS + 1))
        fi
    else
        error_msg "CMake: NOT FOUND"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Check g++
    if command_exists g++; then
        GCC_VERSION=$(g++ -dumpversion)
        GCC_MAJOR=$(echo "$GCC_VERSION" | cut -d. -f1)
        if [ "$GCC_MAJOR" -ge "$MIN_GCC_VERSION" ]; then
            success "G++: $GCC_VERSION (>= $MIN_GCC_VERSION required)"
        else
            error_msg "G++: $GCC_VERSION (< $MIN_GCC_VERSION required)"
            ERRORS=$((ERRORS + 1))
        fi
    else
        error_msg "G++: NOT FOUND"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Check Python
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version | grep -oE '[0-9]+\.[0-9]+')
        if version_gte "$PYTHON_VERSION" "$MIN_PYTHON_VERSION"; then
            success "Python: $PYTHON_VERSION (>= $MIN_PYTHON_VERSION required)"
        else
            error_msg "Python: $PYTHON_VERSION (< $MIN_PYTHON_VERSION required)"
            ERRORS=$((ERRORS + 1))
        fi
    else
        error_msg "Python3: NOT FOUND"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Check pip
    if command_exists pip3 || python3 -m pip --version >/dev/null 2>&1; then
        PIP_VERSION=$(python3 -m pip --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
        success "Pip: $PIP_VERSION"
    else
        error_msg "Pip: NOT FOUND"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Check venv
    if python3 -c "import venv" 2>/dev/null; then
        success "Python venv: Available"
    else
        error_msg "Python venv: NOT AVAILABLE"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Check CUDA (optional)
    if command_exists nvcc; then
        NVCC_VERSION=$(nvcc --version | grep "release" | sed 's/.*release \([0-9.]*\).*/\1/')
        success "CUDA: $NVCC_VERSION (GPU acceleration enabled)"
    else
        warning "CUDA: Not installed (GPU acceleration disabled)"
        WARNINGS=$((WARNINGS + 1))
    fi
    
    # Check OpenMP
    if g++ -fopenmp -x c++ - -o /dev/null 2>/dev/null <<< "int main(){}"; then
        success "OpenMP: Available"
    else
        warning "OpenMP: Not available (CPU parallelization may be limited)"
        WARNINGS=$((WARNINGS + 1))
    fi
    
    echo ""
    if [ $ERRORS -eq 0 ]; then
        success "All required prerequisites are installed!"
        if [ $WARNINGS -gt 0 ]; then
            warning "$WARNINGS optional component(s) missing"
        fi
        return 0
    else
        error_msg "$ERRORS required prerequisite(s) are missing"
        return 1
    fi
}

# ============================================
# Print Next Steps
# ============================================
print_next_steps() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                      Next Steps                            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  1. Install Python dependencies:"
    echo -e "     ${YELLOW}cd $PROJECT_ROOT${NC}"
    echo -e "     ${YELLOW}./scripts/install_requirements.sh${NC}"
    echo ""
    echo "  2. Build the C++ and CUDA components:"
    echo -e "     ${YELLOW}./scripts/build.sh${NC}"
    echo ""
    echo "  3. Start the web application:"
    echo -e "     ${YELLOW}./scripts/start_webapp.sh${NC}"
    echo ""
    echo "  4. Open in browser:"
    echo -e "     ${GREEN}http://localhost:5000${NC}"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

# ============================================
# Main Execution
# ============================================
main() {
    # Check if running as root (not recommended)
    if [ "$EUID" -eq 0 ]; then
        warning "Running as root is not recommended"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    install_system_packages
    check_cuda
    
    if verify_installation; then
        print_next_steps
    else
        echo ""
        error_msg "Please fix the missing prerequisites before continuing."
        exit 1
    fi
}

# Run main
main "$@"
