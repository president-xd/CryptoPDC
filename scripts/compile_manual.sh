#!/bin/bash
#
# CryptoPDC Manual Compilation Script
# Compiles C++ core, CUDA kernels, and Python bindings without CMake
#
# Usage: ./scripts/compile_manual.sh [--no-cuda] [--debug] [--clean] [--help]
#
# Use this script if CMake build fails or for quick development iterations.
#

set -e

# ============================================
# Configuration
# ============================================
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
OBJ_DIR="${BUILD_DIR}/obj"
LIB_DIR="${BUILD_DIR}/lib"
BINDINGS_DIR="${PROJECT_ROOT}/python/cryptopdc/bindings"

ENABLE_CUDA=true
DEBUG_BUILD=false
CLEAN_BUILD=false

# Compiler settings
CXX="g++"
NVCC="nvcc"
JOBS=$(nproc 2>/dev/null || echo 4)

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
        --no-cuda)
            ENABLE_CUDA=false
            shift
            ;;
        --debug)
            DEBUG_BUILD=true
            shift
            ;;
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        -j*)
            JOBS="${1#-j}"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-cuda       Compile without CUDA support"
            echo "  --debug         Build with debug symbols"
            echo "  --clean         Clean before building"
            echo "  -jN             Use N parallel jobs (default: $(nproc 2>/dev/null || echo 4))"
            echo "  --help, -h      Show this help message"
            echo ""
            echo "This script manually compiles CryptoPDC without CMake."
            echo "Useful for quick iterations or when CMake fails."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ============================================
# Header
# ============================================
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          CryptoPDC Manual Compilation Script               ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================
# Check Prerequisites
# ============================================
check_prerequisites() {
    step "Checking prerequisites..."
    
    # Check g++
    if ! command -v "$CXX" &> /dev/null; then
        fatal "g++ not found. Please install build-essential."
    fi
    GCC_VERSION=$("$CXX" -dumpversion)
    success "g++ $GCC_VERSION"
    
    # Check CUDA
    if [ "$ENABLE_CUDA" = true ]; then
        if ! command -v "$NVCC" &> /dev/null; then
            warning "nvcc not found - compiling without CUDA"
            ENABLE_CUDA=false
        else
            NVCC_VERSION=$("$NVCC" --version | grep "release" | sed 's/.*release \([0-9.]*\).*/\1/')
            success "nvcc $NVCC_VERSION"
            
            # Get CUDA library path
            if [ -d "/usr/local/cuda/lib64" ]; then
                CUDA_LIB="/usr/local/cuda/lib64"
            elif [ -d "/usr/lib/x86_64-linux-gnu" ]; then
                CUDA_LIB="/usr/lib/x86_64-linux-gnu"
            else
                warning "CUDA library path not found - may have linking issues"
                CUDA_LIB="/usr/local/cuda/lib64"
            fi
        fi
    fi
    
    # Check Python and pybind11
    if ! command -v python3 &> /dev/null; then
        fatal "python3 not found"
    fi
    
    # Activate venv if exists
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
        success "Virtual environment activated"
    fi
    
    # Get Python flags
    if ! python3 -m pybind11 --includes &> /dev/null; then
        fatal "pybind11 not found. Run ./scripts/install_requirements.sh first."
    fi
    
    PY_INCLUDES=$(python3 -m pybind11 --includes)
    PY_SUFFIX=$(python3-config --extension-suffix)
    success "pybind11 configured (suffix: $PY_SUFFIX)"
    
    echo ""
}

# ============================================
# Setup Build Flags
# ============================================
setup_flags() {
    step "Setting up compiler flags..."
    
    # Base flags
    INCLUDE_FLAGS="-I${PROJECT_ROOT}/core/include -I${PROJECT_ROOT}/cuda/include"
    
    if [ "$DEBUG_BUILD" = true ]; then
        CXX_FLAGS="-g -O0 -std=c++17 -fPIC -DDEBUG $INCLUDE_FLAGS"
        NVCC_FLAGS="-g -G -O0 -std=c++17 -Xcompiler -fPIC $INCLUDE_FLAGS"
        info "Debug build enabled"
    else
        CXX_FLAGS="-O3 -std=c++17 -fPIC -march=native -DNDEBUG $INCLUDE_FLAGS"
        NVCC_FLAGS="-O3 -std=c++17 -Xcompiler -fPIC -use_fast_math $INCLUDE_FLAGS"
        info "Release build (optimized)"
    fi
    
    # Add OpenMP if available
    if "$CXX" -fopenmp -x c++ - -o /dev/null 2>/dev/null <<< "int main(){}"; then
        CXX_FLAGS="$CXX_FLAGS -fopenmp"
        info "OpenMP enabled"
    fi
    
    # CUDA architectures
    CUDA_ARCH="-gencode arch=compute_60,code=sm_60 \
               -gencode arch=compute_70,code=sm_70 \
               -gencode arch=compute_75,code=sm_75 \
               -gencode arch=compute_80,code=sm_80 \
               -gencode arch=compute_86,code=sm_86"
    
    echo ""
}

# ============================================
# Clean Build Directory
# ============================================
clean_build() {
    if [ "$CLEAN_BUILD" = true ]; then
        step "Cleaning build directory..."
        rm -rf "$OBJ_DIR"
        rm -f "$BINDINGS_DIR"/*.so
        rm -f "$BINDINGS_DIR"/*.pyd
        success "Clean complete"
    fi
}

# ============================================
# Create Directories
# ============================================
create_directories() {
    step "Creating build directories..."
    mkdir -p "$OBJ_DIR"
    mkdir -p "$LIB_DIR"
    mkdir -p "$BINDINGS_DIR"
    success "Directories created"
}

# ============================================
# Compile CUDA Kernels
# ============================================
compile_cuda() {
    if [ "$ENABLE_CUDA" = false ]; then
        warning "CUDA compilation skipped"
        return 0
    fi
    
    echo ""
    step "Compiling CUDA kernels..."
    
    CUDA_SOURCES=(
        "cuda/src/hash/md5_kernel.cu"
        "cuda/src/hash/sha1_kernel.cu"
        "cuda/src/hash/sha256_kernel.cu"
        "cuda/src/hash/sha512_kernel.cu"
        "cuda/src/hash/sha3_kernel.cu"
        "cuda/src/hash/sha224_kernel.cu"
        "cuda/src/hash/sha384_kernel.cu"
        "cuda/src/hash/md2_kernel.cu"
        "cuda/src/hash/md4_kernel.cu"
        "cuda/src/hash/md6_kernel.cu"
        "cuda/src/hash/ntlm_kernel.cu"
        "cuda/src/hash/ripemd_kernel.cu"
        "cuda/src/hash/whirlpool_kernel.cu"
        "cuda/src/hash/checksum_kernel.cu"
        "cuda/src/symmetric/aes128_kernel.cu"
        "cuda/src/symmetric/aes192_kernel.cu"
        "cuda/src/symmetric/aes256_kernel.cu"
    )
    
    COMPILED=0
    FAILED=0
    
    for src in "${CUDA_SOURCES[@]}"; do
        src_path="$PROJECT_ROOT/$src"
        if [ -f "$src_path" ]; then
            obj_name=$(basename "$src" .cu).o
            info "  Compiling $(basename "$src")..."
            if "$NVCC" $NVCC_FLAGS $CUDA_ARCH -c "$src_path" -o "$OBJ_DIR/$obj_name" 2>/dev/null; then
                COMPILED=$((COMPILED + 1))
            else
                warning "    Failed to compile $(basename "$src")"
                FAILED=$((FAILED + 1))
            fi
        fi
    done
    
    if [ $COMPILED -gt 0 ]; then
        success "CUDA kernels compiled: $COMPILED succeeded, $FAILED failed"
    else
        warning "No CUDA kernels compiled"
    fi
}

# ============================================
# Compile C++ Core
# ============================================
compile_cpp() {
    echo ""
    step "Compiling C++ core library..."
    
    CPP_SOURCES=(
        "core/src/common/utils.cpp"
        "core/src/common/types.cpp"
        "core/src/algorithms/hash/md5.cpp"
        "core/src/algorithms/hash/sha1.cpp"
        "core/src/algorithms/hash/sha256.cpp"
        "core/src/algorithms/hash/sha512.cpp"
        "core/src/algorithms/hash/sha3.cpp"
        "core/src/algorithms/hash/sha224.cpp"
        "core/src/algorithms/hash/sha384.cpp"
        "core/src/algorithms/hash/md2.cpp"
        "core/src/algorithms/hash/md4.cpp"
        "core/src/algorithms/hash/md6.cpp"
        "core/src/algorithms/hash/ntlm.cpp"
        "core/src/algorithms/hash/ripemd.cpp"
        "core/src/algorithms/hash/whirlpool.cpp"
        "core/src/algorithms/hash/checksum.cpp"
        "core/src/algorithms/symmetric/aes.cpp"
        "core/src/cpu_cracker.cpp"
    )
    
    COMPILED=0
    FAILED=0
    
    for src in "${CPP_SOURCES[@]}"; do
        src_path="$PROJECT_ROOT/$src"
        if [ -f "$src_path" ]; then
            obj_name=$(basename "$src" .cpp).o
            info "  Compiling $(basename "$src")..."
            if "$CXX" $CXX_FLAGS -c "$src_path" -o "$OBJ_DIR/$obj_name" 2>/dev/null; then
                COMPILED=$((COMPILED + 1))
            else
                warning "    Failed to compile $(basename "$src")"
                FAILED=$((FAILED + 1))
            fi
        fi
    done
    
    success "C++ core compiled: $COMPILED succeeded, $FAILED failed"
}

# ============================================
# Compile Python Bindings
# ============================================
compile_bindings() {
    echo ""
    step "Compiling Python bindings..."
    
    BINDINGS_SRC="$PROJECT_ROOT/python/cryptopdc/bindings/core_bindings.cpp"
    
    if [ ! -f "$BINDINGS_SRC" ]; then
        fatal "Bindings source not found: $BINDINGS_SRC"
    fi
    
    info "  Compiling core_bindings.cpp..."
    "$CXX" $CXX_FLAGS $PY_INCLUDES -c "$BINDINGS_SRC" -o "$OBJ_DIR/bindings.o"
    
    success "Bindings object compiled"
}

# ============================================
# Link Everything
# ============================================
link_library() {
    echo ""
    step "Linking shared library..."
    
    OUTPUT_FILE="$BINDINGS_DIR/cryptopdc_bindings$PY_SUFFIX"
    
    # Collect all object files
    OBJ_FILES=$(find "$OBJ_DIR" -name "*.o" 2>/dev/null | tr '\n' ' ')
    
    if [ -z "$OBJ_FILES" ]; then
        fatal "No object files found to link"
    fi
    
    # Link flags
    LINK_FLAGS="-shared"
    
    if "$CXX" -fopenmp -x c++ - -o /dev/null 2>/dev/null <<< "int main(){}"; then
        LINK_FLAGS="$LINK_FLAGS -fopenmp"
    fi
    
    if [ "$ENABLE_CUDA" = true ]; then
        LINK_FLAGS="$LINK_FLAGS -L$CUDA_LIB -lcudart"
    fi
    
    info "  Linking to $OUTPUT_FILE..."
    $CXX $LINK_FLAGS -o "$OUTPUT_FILE" $OBJ_FILES $LINK_FLAGS
    
    if [ -f "$OUTPUT_FILE" ]; then
        FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
        success "Library created: $(basename "$OUTPUT_FILE") ($FILE_SIZE)"
    else
        fatal "Failed to create library"
    fi
}

# ============================================
# Verify Build
# ============================================
verify_build() {
    echo ""
    step "Verifying build..."
    
    # Set PYTHONPATH
    export PYTHONPATH="$PROJECT_ROOT/python:$PYTHONPATH"
    
    # Try to import
    if python3 -c "from cryptopdc.bindings import cryptopdc_bindings; print('  Available functions:', len(dir(cryptopdc_bindings)))" 2>/dev/null; then
        success "Python import test passed"
        
        # List some available functions
        python3 -c "
from cryptopdc.bindings import cryptopdc_bindings as core
funcs = [f for f in dir(core) if not f.startswith('_')]
print('  Key functions:')
for f in funcs[:10]:
    print(f'    - {f}')
if len(funcs) > 10:
    print(f'    ... and {len(funcs)-10} more')
" 2>/dev/null || true
    else
        warning "Python import test failed"
        info "This may be due to missing CUDA libraries at runtime"
        info "Try: export LD_LIBRARY_PATH=/usr/local/cuda/lib64:\$LD_LIBRARY_PATH"
    fi
}

# ============================================
# Print Summary
# ============================================
print_summary() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║               Manual Compilation Complete!                 ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Output: $BINDINGS_DIR/cryptopdc_bindings$PY_SUFFIX"
    echo ""
    echo "  To use:"
    echo -e "    ${YELLOW}export PYTHONPATH=$PROJECT_ROOT/python:\$PYTHONPATH${NC}"
    if [ "$ENABLE_CUDA" = true ]; then
        echo -e "    ${YELLOW}export LD_LIBRARY_PATH=$CUDA_LIB:\$LD_LIBRARY_PATH${NC}"
    fi
    echo -e "    ${YELLOW}python3 -c \"from cryptopdc.bindings import cryptopdc_bindings\"${NC}"
    echo ""
    echo "  To start webapp:"
    echo -e "    ${YELLOW}./scripts/start_webapp.sh${NC}"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

# ============================================
# Main Execution
# ============================================
main() {
    cd "$PROJECT_ROOT"
    
    check_prerequisites
    setup_flags
    clean_build
    create_directories
    compile_cuda
    compile_cpp
    compile_bindings
    link_library
    verify_build
    print_summary
}

# Run main
main "$@"
