#!/bin/bash
# CryptoPDC Build Script using CMake
# Usage: ./scripts/build.sh [clean|debug|release] [-jN]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
BUILD_TYPE="Release"
JOBS=$(nproc)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        clean)
            echo -e "${YELLOW}Cleaning build directory...${NC}"
            rm -rf "${BUILD_DIR}"
            echo -e "${GREEN}Clean complete!${NC}"
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
        --help|-h)
            echo "Usage: $0 [clean|debug|release] [-jN]"
            echo ""
            echo "Commands:"
            echo "  clean    Remove build directory"
            echo "  debug    Build in Debug mode"
            echo "  release  Build in Release mode (default)"
            echo ""
            echo "Options:"
            echo "  -jN      Use N parallel jobs (default: nproc)"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   CryptoPDC Build System${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Build type: ${GREEN}${BUILD_TYPE}${NC}"
echo -e "Build jobs: ${GREEN}${JOBS}${NC}"
echo ""

# Create build directory
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Run CMake configuration
echo -e "${YELLOW}Configuring CMake...${NC}"
cmake .. \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DBUILD_PYTHON_BINDINGS=ON \
    -DENABLE_OPENMP=ON \
    -DBUILD_TESTING=OFF \
    -DBUILD_BENCHMARKS=OFF

echo ""
echo -e "${YELLOW}Building with ${JOBS} jobs...${NC}"
cmake --build . -j${JOBS}

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   Build Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Python bindings installed to:"
echo -e "  ${BLUE}${PROJECT_ROOT}/python/cryptopdc/bindings/${NC}"
echo ""
echo -e "To use the module, run:"
echo -e "  ${YELLOW}export PYTHONPATH=${PROJECT_ROOT}/python:\$PYTHONPATH${NC}"
echo -e "  ${YELLOW}python3 -c \"from cryptopdc.bindings import cryptopdc_bindings; print('OK')\"${NC}"
echo ""
