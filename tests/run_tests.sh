#!/bin/bash
# CryptoPDC Test Runner Script
# Runs all tests: C++ unit tests, CUDA tests, and Python tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}     CryptoPDC Test Suite Runner       ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to print section header
print_section() {
    echo ""
    echo -e "${YELLOW}----------------------------------------${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
}

# Function to check if build exists
check_build() {
    if [ ! -d "$BUILD_DIR" ] || [ ! -f "$BUILD_DIR/Makefile" ]; then
        echo -e "${RED}Build directory not found or not configured.${NC}"
        echo "Please build the project first:"
        echo "  mkdir -p build && cd build && cmake .. && make"
        exit 1
    fi
}

# Function to run C++ tests
run_cpp_tests() {
    print_section "Running C++ Unit Tests"
    
    cd "$BUILD_DIR"
    
    # Build tests if needed
    echo "Building tests..."
    make test_hash_algorithms test_cpu_cracker -j$(nproc) 2>/dev/null || {
        echo -e "${YELLOW}Note: Some tests may not be available yet${NC}"
    }
    
    # Run hash algorithm tests
    if [ -f "$BUILD_DIR/tests/test_hash_algorithms" ]; then
        echo ""
        echo "Running hash algorithm tests..."
        ./tests/test_hash_algorithms --gtest_color=yes
    else
        echo -e "${YELLOW}test_hash_algorithms not found, skipping${NC}"
    fi
    
    # Run CPU cracker tests
    if [ -f "$BUILD_DIR/tests/test_cpu_cracker" ]; then
        echo ""
        echo "Running CPU cracker tests..."
        ./tests/test_cpu_cracker --gtest_color=yes
    else
        echo -e "${YELLOW}test_cpu_cracker not found, skipping${NC}"
    fi
}

# Function to run CUDA tests
run_cuda_tests() {
    print_section "Running CUDA Tests"
    
    # Check if CUDA is available
    if ! command -v nvcc &> /dev/null; then
        echo -e "${YELLOW}CUDA not available, skipping CUDA tests${NC}"
        return
    fi
    
    cd "$BUILD_DIR"
    
    # Build CUDA tests
    make test_cuda_hash_kernels test_cuda_symmetric_kernels -j$(nproc) 2>/dev/null || {
        echo -e "${YELLOW}Note: CUDA tests may not be available${NC}"
    }
    
    # Run CUDA hash kernel tests
    if [ -f "$BUILD_DIR/tests/test_cuda_hash_kernels" ]; then
        echo ""
        echo "Running CUDA hash kernel tests..."
        ./tests/test_cuda_hash_kernels --gtest_color=yes
    else
        echo -e "${YELLOW}test_cuda_hash_kernels not found, skipping${NC}"
    fi
    
    # Run CUDA symmetric kernel tests
    if [ -f "$BUILD_DIR/tests/test_cuda_symmetric_kernels" ]; then
        echo ""
        echo "Running CUDA symmetric kernel tests..."
        ./tests/test_cuda_symmetric_kernels --gtest_color=yes
    else
        echo -e "${YELLOW}test_cuda_symmetric_kernels not found, skipping${NC}"
    fi
}

# Function to run Python tests
run_python_tests() {
    print_section "Running Python Tests"
    
    cd "$PROJECT_ROOT"
    
    # Set up Python path
    export PYTHONPATH="$PROJECT_ROOT/python:$BUILD_DIR/python:$PYTHONPATH"
    
    # Run Python binding tests
    echo "Running Python binding tests..."
    python3 -m pytest tests/python/ -v --tb=short 2>/dev/null || {
        # Fallback to unittest if pytest not available
        echo "pytest not found, using unittest..."
        python3 -m unittest discover -s tests/python -v
    }
}

# Function to run CTest
run_ctest() {
    print_section "Running CTest Suite"
    
    cd "$BUILD_DIR"
    ctest --output-on-failure --parallel $(nproc)
}

# Main execution
main() {
    local test_type="${1:-all}"
    
    check_build
    
    case "$test_type" in
        cpp)
            run_cpp_tests
            ;;
        cuda)
            run_cuda_tests
            ;;
        python)
            run_python_tests
            ;;
        ctest)
            run_ctest
            ;;
        all)
            run_cpp_tests
            run_cuda_tests
            run_python_tests
            ;;
        *)
            echo "Usage: $0 [cpp|cuda|python|ctest|all]"
            echo ""
            echo "Options:"
            echo "  cpp     - Run C++ unit tests only"
            echo "  cuda    - Run CUDA kernel tests only"
            echo "  python  - Run Python binding tests only"
            echo "  ctest   - Run all tests via CTest"
            echo "  all     - Run all tests (default)"
            exit 1
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}     Test Suite Completed              ${NC}"
    echo -e "${GREEN}========================================${NC}"
}

main "$@"
