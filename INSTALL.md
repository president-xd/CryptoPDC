# CryptoPDC Installation Guide

This guide provides step-by-step instructions for installing and running CryptoPDC on your system.

## Table of Contents
- [System Requirements](#system-requirements)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Installation](#detailed-installation)
- [Running the Application](#running-the-application)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

### Hardware
| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| GPU | NVIDIA (CUDA 6.0+) | NVIDIA RTX series |
| Storage | 10 GB | 20+ GB |

### Operating System
- **Linux**: Ubuntu 20.04+, Debian 11+, CentOS 8+, Fedora 35+
- **Windows**: Windows 10/11 with WSL2 (Linux subsystem)

---

## Prerequisites

### 1. NVIDIA GPU Driver & CUDA Toolkit

```bash
# Check if NVIDIA driver is installed
nvidia-smi

# Install CUDA Toolkit (Ubuntu/Debian)
sudo apt update
sudo apt install nvidia-cuda-toolkit

# Verify CUDA installation
nvcc --version
```

**Required**: CUDA Toolkit 11.5 or newer

### 2. C++ Compiler (GCC 9+ or Clang 10+)

```bash
# Ubuntu/Debian
sudo apt install build-essential gcc g++

# Verify
gcc --version
g++ --version
```

### 3. CMake (3.18+)

```bash
# Ubuntu/Debian
sudo apt install cmake

# Verify
cmake --version
```

### 4. Python (3.10+)

```bash
# Ubuntu/Debian
sudo apt install python3 python3-pip python3-venv python3-dev

# Verify
python3 --version
```

### 5. Git

```bash
sudo apt install git
```

---

## Quick Start

For users who want to get up and running quickly:

```bash
# 1. Clone the repository
git clone https://github.com/cryptopdc/cryptopdc.git
cd cryptopdc

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Build the C++/CUDA components
./scripts/build.sh

# 5. Run the web application
PYTHONPATH=$(pwd)/python python webapp/app.py

# 6. Open browser at http://localhost:5000
```

---

## Detailed Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/cryptopdc/cryptopdc.git
cd cryptopdc
```

### Step 2: Set Up Python Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/macOS
# OR
.\venv\Scripts\activate   # Windows

# Upgrade pip
pip install --upgrade pip
```

### Step 3: Install Python Dependencies

```bash
pip install -r requirements.txt
```

The main dependencies are:
- `flask` - Web framework
- `flask-socketio` - WebSocket support
- `flask-cors` - Cross-origin resource sharing
- `pyzmq` - ZeroMQ for distributed messaging
- `pybind11` - C++/Python bindings

### Step 4: Build C++/CUDA Components

#### Option A: Using the build script (Recommended)

```bash
# Standard release build
./scripts/build.sh

# Debug build (with symbols)
./scripts/build.sh debug

# Clean build (removes previous build)
./scripts/build.sh clean
./scripts/build.sh

# Specify parallel jobs
./scripts/build.sh -j8
```

#### Option B: Manual CMake build

```bash
# Create build directory
mkdir -p build && cd build

# Configure with CMake
cmake -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTING=OFF \
      -DBUILD_BENCHMARKS=OFF \
      ..

# Build (use number of CPU cores)
make -j$(nproc)

# Return to project root
cd ..
```

### Step 5: Verify Installation

```bash
# Test Python bindings
PYTHONPATH=$(pwd)/python python3 -c "
from cryptopdc.bindings import cryptopdc_bindings as core
print('Available functions:', dir(core))
md5 = core.MD5()
result = md5.hash('test')
print('MD5 of \"test\":', core.bytes_to_hex(result))
"
```

Expected output:
```
Available functions: ['AES128', 'AES192', 'AES256', 'MD5', 'SHA1', ...]
MD5 of "test": 098f6bcd4621d373cade4e832627b4f6
```

---

## Running the Application

### Start the Web Interface

```bash
# Activate virtual environment (if not already)
source venv/bin/activate

# Set Python path and run
PYTHONPATH=$(pwd)/python python webapp/app.py
```

The application will start on:
- **Local**: http://localhost:5000
- **Network**: http://<your-ip>:5000

### Start a Worker Node

To enable distributed cracking, start worker nodes:

```bash
# On the same machine
PYTHONPATH=$(pwd)/python python -m cryptopdc.distributed.worker

# On a remote machine (specify master IP)
PYTHONPATH=$(pwd)/python python -m cryptopdc.distributed.worker \
    --master-ip <master-ip-address> \
    --device-id 0
```

### Run from Scripts

```bash
# Use the provided start script
./scripts/start_webapp.sh
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PYTHONPATH` | Path to Python modules | `./python` |
| `CUDA_VISIBLE_DEVICES` | GPU device IDs to use | All GPUs |
| `OMP_NUM_THREADS` | OpenMP thread count | Auto |

### Ports Used

| Port | Service | Description |
|------|---------|-------------|
| 5000 | Flask | Web interface |
| 5555 | ZeroMQ | Task queue (PUSH/PULL) |
| 5556 | ZeroMQ | Result collector |
| 5557 | ZeroMQ | Control messages |

---

## Directory Structure

```
CryptoPDC/
├── build/              # CMake build output
├── core/               # C++ core library
│   ├── include/        # Header files
│   └── src/            # Source files
├── cuda/               # CUDA GPU kernels
│   ├── include/        # CUDA headers
│   └── src/            # CUDA source files
├── python/             # Python package
│   └── cryptopdc/
│       ├── bindings/   # Compiled Python bindings (.so)
│       ├── distributed/# Master/Worker implementation
│       └── api/        # REST API
├── webapp/             # Flask web application
│   ├── static/         # CSS, JavaScript
│   └── templates/      # HTML templates
├── wordlists/          # Password wordlists
├── scripts/            # Build and run scripts
├── venv/               # Python virtual environment
├── CMakeLists.txt      # CMake configuration
├── requirements.txt    # Python dependencies
└── INSTALL.md          # This file
```

---

## Troubleshooting

### Common Issues

#### 1. CUDA not found

```
CMake Error: Could not find CUDAToolkit
```

**Solution**: Install CUDA Toolkit and ensure `nvcc` is in PATH:
```bash
export PATH=/usr/local/cuda/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH
```

#### 2. Python bindings import error

```
ImportError: libcudart.so: cannot open shared object file
```

**Solution**: Add CUDA libraries to library path:
```bash
export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH
```

#### 3. OpenMP not found

```
Could not find OpenMP
```

**Solution**: Install OpenMP:
```bash
# Ubuntu/Debian
sudo apt install libomp-dev

# CentOS/RHEL
sudo yum install libomp-devel
```

#### 4. Permission denied on build script

```bash
chmod +x scripts/build.sh
chmod +x scripts/start_webapp.sh
```

#### 5. Port already in use

```
OSError: [Errno 98] Address already in use
```

**Solution**: Kill the existing process or use a different port:
```bash
# Find process using port 5000
lsof -i :5000

# Kill it
kill -9 <PID>
```

### Getting Help

If you encounter issues:

1. Check the [GitHub Issues](https://github.com/cryptopdc/cryptopdc/issues)
2. Review build logs in `build/CMakeFiles/CMakeOutput.log`
3. Run with debug logging:
   ```bash
   PYTHONPATH=$(pwd)/python python webapp/app.py --debug
   ```

---

## Uninstallation

To completely remove CryptoPDC:

```bash
# Deactivate virtual environment
deactivate

# Remove the project directory
cd ..
rm -rf cryptopdc
```

---

## Next Steps

After installation:

1. **Open the Web UI**: http://localhost:5000
2. **Submit a test task**: Try cracking MD5 hash `098f6bcd4621d373cade4e832627b4f6` (password: "test")
3. **Read the documentation**: See `PROJECT_DOCUMENTATION.md` for detailed architecture info
4. **Start workers**: For distributed cracking, launch worker nodes on other machines

---

## License

CryptoPDC is released under the MIT License. See `LICENSE` file for details.
