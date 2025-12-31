#!/bin/bash
#
# CryptoPDC Build Script using CMake
# Builds C++ core library, CUDA kernels, and Python bindings
#
# Usage: ./scripts/build.sh [clean|debug|release] [-jN] [--no-cuda] [--help]
#

set -e

# ============================================
# Configuration
# ============================================
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
BUILD_TYPE="Release"
JOBS=$(nproc 2>/dev/null || echo 4)
ENABLE_CUDA=true
BUILD_TESTS=false
BUILD_BENCHMARKS=false
VERBOSE=false

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
        clean)
            echo -e "${YELLOW}Cleaning build directory...${NC}"
            rm -rf "${BUILD_DIR}"
            rm -f "${PROJECT_ROOT}/python/cryptopdc/bindings/"*.so
            rm -f "${PROJECT_ROOT}/python/cryptopdc/bindings/"*.pyd
            success "Clean complete!"
            exit 0
            ;;
        debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        release)
            BUILD_TYPE="Release"
            shift
            ;;
        -j*)
            JOBS="${1#-j}"
            shift
            ;;
        --no-cuda)
            ENABLE_CUDA=false
            shift
            ;;
        --with-tests)
            BUILD_TESTS=true
            shift
            ;;
        --with-benchmarks)
            BUILD_BENCHMARKS=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [COMMAND] [OPTIONS]"
            echo ""
            echo "Commands:"
            echo "  clean           Remove build directory and compiled bindings"
            echo "  debug           Build in Debug mode (with symbols, no optimization)"
            echo "  release         Build in Release mode (default, optimized)"
            echo ""
            echo "Options:"
            echo "  -jN             Use N parallel jobs (default: $(nproc 2>/dev/null || echo 4))"
            echo "  --no-cuda       Build without CUDA support"
            echo "  --with-tests    Build test suite"
            echo "  --with-benchmarks  Build benchmarks"
            echo "  --verbose, -v   Verbose output"
            echo "  --help, -h      Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0              Build in release mode"
            echo "  $0 debug -j8   Build debug with 8 parallel jobs"
            echo "  $0 clean        Clean all build artifacts"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ============================================
# Header
# ============================================
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              CryptoPDC Build System                        ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Build Type:    ${GREEN}${BUILD_TYPE}${NC}"
echo "  Parallel Jobs: ${GREEN}${JOBS}${NC}"
echo "  CUDA:          ${GREEN}$([ "$ENABLE_CUDA" = true ] && echo "Enabled" || echo "Disabled")${NC}"
echo "  Tests:         ${GREEN}$([ "$BUILD_TESTS" = true ] && echo "Yes" || echo "No")${NC}"
echo ""

# ============================================
# Check Prerequisites
# ============================================
check_prerequisites() {
    step "Checking build prerequisites..."
    
    ERRORS=0
    
    # Check cmake
    if ! command -v cmake &> /dev/null; then
        error_msg "cmake not found"
        ERRORS=$((ERRORS + 1))
    else
        CMAKE_VERSION=$(cmake --version | head -n1 | grep -oE '[0-9]+\.[0-9]+')
        success "cmake $CMAKE_VERSION"
    fi
    
    # Check g++
    if ! command -v g++ &> /dev/null; then
        error_msg "g++ not found"
        ERRORS=$((ERRORS + 1))
    else
        GCC_VERSION=$(g++ -dumpversion)
        success "g++ $GCC_VERSION"
    fi
    
    # Check CUDA
    if [ "$ENABLE_CUDA" = true ]; then
        if ! command -v nvcc &> /dev/null; then
            warning "nvcc not found - CUDA will be disabled"
            ENABLE_CUDA=false
        else
            NVCC_VERSION=$(nvcc --version | grep "release" | sed 's/.*release \([0-9.]*\).*/\1/')
            success "nvcc $NVCC_VERSION"
        fi
    fi
    
    # Check Python and pybind11
    if ! command -v python3 &> /dev/null; then
        error_msg "python3 not found"
        ERRORS=$((ERRORS + 1))
    else
        # Activate venv if it exists
        if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
            source "$PROJECT_ROOT/venv/bin/activate"
            success "Virtual environment activated"
        fi
        
        PYTHON_VERSION=$(python3 --version | grep -oE '[0-9]+\.[0-9]+')
        success "python3 $PYTHON_VERSION"
        
        # Check pybind11
        if python3 -c "import pybind11" 2>/dev/null; then
            PYBIND_VERSION=$(python3 -c "import pybind11; print(pybind11.__version__)")
            success "pybind11 $PYBIND_VERSION"
        else
            warning "pybind11 not found - run ./scripts/install_requirements.sh first"
        fi
    fi
    
    echo ""
    
    if [ $ERRORS -gt 0 ]; then
        fatal "$ERRORS required tool(s) missing. Please install prerequisites first."
    fi
}

# ============================================
# Configure with CMake
# ============================================
configure_cmake() {
    step "Creating build directory..."
    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"
    
    step "Configuring CMake..."
    
    CMAKE_ARGS=(
        "-DCMAKE_BUILD_TYPE=${BUILD_TYPE}"
        "-DBUILD_PYTHON_BINDINGS=ON"
        "-DENABLE_OPENMP=ON"
        "-DBUILD_TESTING=$([ "$BUILD_TESTS" = true ] && echo "ON" || echo "OFF")"
        "-DBUILD_BENCHMARKS=$([ "$BUILD_BENCHMARKS" = true ] && echo "ON" || echo "OFF")"
    )
    
    # Add CUDA architectures if CUDA is enabled
    if [ "$ENABLE_CUDA" = true ]; then
        CMAKE_ARGS+=("-DCMAKE_CUDA_ARCHITECTURES=60;61;70;75;80;86;89")
    fi
    
    if [ "$VERBOSE" = true ]; then
        CMAKE_ARGS+=("-DCMAKE_VERBOSE_MAKEFILE=ON")
    fi
    
    cmake .. "${CMAKE_ARGS[@]}"
    
    success "CMake configuration complete"
}

# ============================================
# Build
# ============================================
build_project() {
    step "Building with ${JOBS} parallel jobs..."
    
    if [ "$VERBOSE" = true ]; then
        cmake --build . -j${JOBS} --verbose
    else
        cmake --build . -j${JOBS}
    fi
    
    success "Build complete"
}

# ============================================
# Verify Build Output
# ============================================
verify_build() {
    echo ""
    step "Verifying build output..."
    
    BINDINGS_PATH="${PROJECT_ROOT}/python/cryptopdc/bindings"
    BINDING_FILE=$(ls "$BINDINGS_PATH"/cryptopdc_bindings*.so 2>/dev/null || true)
    
    if [ -n "$BINDING_FILE" ]; then
        success "Python bindings: $(basename "$BINDING_FILE")"
        
        # Test import
        export PYTHONPATH="${PROJECT_ROOT}/python:$PYTHONPATH"
        if python3 -c "from cryptopdc.bindings import cryptopdc_bindings; print('  Functions:', len(dir(cryptopdc_bindings)))" 2>/dev/null; then
            success "Python import test passed"
        else
            warning "Python import test failed - bindings may not work correctly"
        fi
    else
        warning "Python bindings not found - may need manual compilation"
        info "Try: ./scripts/compile_manual.sh"
    fi
    
    # Check for test executables
    if [ "$BUILD_TESTS" = true ]; then
        if [ -f "${BUILD_DIR}/bin/test_hash_algorithms" ]; then
            success "Test executables built"
        fi
    fi
}

# ============================================
# Print Summary
# ============================================
print_summary() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    Build Complete!                         ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Build directory: ${BUILD_DIR}"
    echo "  Python bindings: ${PROJECT_ROOT}/python/cryptopdc/bindings/"
    echo ""
    echo "  To use the Python bindings:"
    echo -e "    ${YELLOW}export PYTHONPATH=${PROJECT_ROOT}/python:\$PYTHONPATH${NC}"
    echo -e "    ${YELLOW}python3 -c \"from cryptopdc.bindings import cryptopdc_bindings; print('OK')\"${NC}"
    echo ""
    echo "  To start the webapp:"
    echo -e "    ${YELLOW}./scripts/start_webapp.sh${NC}"
    echo ""
    if [ "$BUILD_TESTS" = true ]; then
        echo "  To run tests:"
        echo -e "    ${YELLOW}cd ${BUILD_DIR} && ctest --output-on-failure${NC}"
        echo ""
    fi
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

# ============================================
# Main Execution
# ============================================
main() {
    check_prerequisites
    configure_cmake
    build_project
    verify_build
    print_summary
}

# Run main
main "$@"
