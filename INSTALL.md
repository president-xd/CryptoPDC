# CryptoPDC Installation Guide

This guide provides step-by-step instructions for installing and running CryptoPDC on your system.

## Table of Contents
- [System Requirements](#system-requirements)
- [Quick Start (TL;DR)](#quick-start-tldr)
- [Step-by-Step Installation](#step-by-step-installation)
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

### Software
| Component | Minimum Version |
|-----------|-----------------|
| OS | Linux (Ubuntu 20.04+, Debian 11+, Fedora 35+) |
| GCC/G++ | 9.0+ |
| CMake | 3.18+ |
| Python | 3.10+ |
| CUDA | 11.5+ (optional, for GPU acceleration) |

---

## Quick Start (TL;DR)

For experienced users who want to get running quickly:

```bash
# Clone the repository
git clone https://github.com/cryptopdc/cryptopdc.git
cd cryptopdc

# Step 1: Install system prerequisites
./scripts/prereqs.sh

# Step 2: Install Python dependencies (creates venv)
./scripts/install_requirements.sh

# Step 3: Build C++ and CUDA components
./scripts/build.sh

# Step 4: Start the application
./scripts/start_webapp.sh

# Open in browser
# http://localhost:5000
```

---

## Step-by-Step Installation

### Step 1: Install System Prerequisites

The prerequisites script installs all required system packages:

```bash
./scripts/prereqs.sh
```

**What this script does:**
- Installs build tools (cmake, g++, make)
- Installs Python 3.10+ with pip and venv
- Checks for CUDA toolkit
- Installs OpenMP for CPU parallelization
- Verifies all installations

**Options:**
```bash
./scripts/prereqs.sh --help          # Show all options
./scripts/prereqs.sh --skip-cuda     # Skip CUDA check (CPU-only mode)
```

### Step 2: Install Python Dependencies

This script creates a Python virtual environment and installs all required packages:

```bash
./scripts/install_requirements.sh
```

**What this script does:**
- Creates a Python virtual environment at `./venv`
- Upgrades pip, setuptools, and wheel
- Installs all packages from `requirements.txt`
- Installs pybind11 for C++ bindings
- Verifies all package imports

**Options:**
```bash
./scripts/install_requirements.sh --help    # Show all options
./scripts/install_requirements.sh --force   # Force reinstall
./scripts/install_requirements.sh --dev     # Include dev dependencies
```

**To activate the environment manually:**
```bash
source venv/bin/activate
# or use the helper script
source activate.sh
```

### Step 3: Build C++ and CUDA Components

Build the high-performance C++ core and CUDA kernels:

```bash
./scripts/build.sh
```

**What this script does:**
- Configures the build with CMake
- Compiles C++ core library (hash algorithms, crackers)
- Compiles CUDA kernels (GPU-accelerated implementations)
- Builds Python bindings using pybind11
- Verifies the build output

**Options:**
```bash
./scripts/build.sh --help           # Show all options
./scripts/build.sh clean            # Clean build directory
./scripts/build.sh debug            # Build with debug symbols
./scripts/build.sh -j8              # Use 8 parallel jobs
./scripts/build.sh --no-cuda        # Build without CUDA support
./scripts/build.sh --with-tests     # Build test suite
```

**Alternative: Manual compilation (if CMake fails):**
```bash
./scripts/compile_manual.sh
```

### Step 4: Start the Application

Launch the complete CryptoPDC system:

```bash
./scripts/start_webapp.sh
```

**What this script does:**
- Activates the virtual environment
- Sets up PYTHONPATH and library paths
- Starts Flask web server on port 5000
- Starts ZeroMQ task queue on port 5555
- Starts result collector on port 5556
- Starts worker node(s) for processing

**Options:**
```bash
./scripts/start_webapp.sh --help           # Show all options
./scripts/start_webapp.sh --no-worker      # Don't start workers
./scripts/start_webapp.sh --workers 4      # Start 4 workers
./scripts/start_webapp.sh --port 8080      # Use different port
./scripts/start_webapp.sh --background     # Run as daemon
./scripts/start_webapp.sh --stop           # Stop all services
./scripts/start_webapp.sh --status         # Check service status
```

---

## Running the Application

### Services

After starting, the following services are available:

| Service | URL/Port | Description |
|---------|----------|-------------|
| Web Interface | http://localhost:5000 | Main UI for submitting tasks |
| Task Queue | tcp://localhost:5555 | ZeroMQ PUSH socket for tasks |
| Results | tcp://localhost:5556 | ZeroMQ PULL socket for results |
| Control | tcp://localhost:5557 | Control channel for workers |

### Starting Additional Workers

For distributed processing across multiple machines:

```bash
# On the worker machine:
./scripts/start_worker.sh --master <MASTER_IP> --device 0
```

**Options:**
```bash
./scripts/start_worker.sh --help                    # Show all options
./scripts/start_worker.sh --master 192.168.1.100   # Connect to remote master
./scripts/start_worker.sh --device 1               # Use GPU 1
./scripts/start_worker.sh --background             # Run as daemon
```

### Example: Distributed Setup

**Master Node:**
```bash
./scripts/start_webapp.sh --no-worker
```

**Worker Nodes:**
```bash
# Worker 1 (GPU 0)
./scripts/start_worker.sh --master 192.168.1.100 --device 0

# Worker 2 (GPU 1)
./scripts/start_worker.sh --master 192.168.1.100 --device 1
```

---

## Troubleshooting

### Python bindings not found

**Symptom:**
```
ImportError: No module named 'cryptopdc_bindings'
```

**Solution:**
```bash
# Rebuild bindings
./scripts/build.sh clean
./scripts/build.sh

# Or use manual compilation
./scripts/compile_manual.sh
```

### CUDA not detected

**Symptom:**
```
CUDA: Not installed (GPU acceleration disabled)
```

**Solution:**
1. Install NVIDIA drivers: `sudo apt install nvidia-driver-535`
2. Install CUDA toolkit: `sudo apt install nvidia-cuda-toolkit`
3. Add CUDA to PATH:
   ```bash
   echo 'export PATH=/usr/local/cuda/bin:$PATH' >> ~/.bashrc
   echo 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
   source ~/.bashrc
   ```

### Port already in use

**Symptom:**
```
Port 5000 is already in use
```

**Solution:**
```bash
# Option 1: Use different port
./scripts/start_webapp.sh --port 8080

# Option 2: Kill existing process
./scripts/start_webapp.sh --stop
./scripts/start_webapp.sh
```

### Worker cannot connect to master

**Symptom:**
```
Cannot reach master at 192.168.1.100:5555
```

**Solution:**
1. Check firewall rules on master: `sudo ufw allow 5555/tcp`
2. Ensure master is binding to 0.0.0.0 (not localhost)
3. Verify network connectivity: `ping 192.168.1.100`

### Virtual environment issues

**Symptom:**
```
ModuleNotFoundError: No module named 'flask'
```

**Solution:**
```bash
# Reinstall Python dependencies
./scripts/install_requirements.sh --force

# Or manually activate venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Scripts Summary

| Script | Purpose |
|--------|---------|
| `prereqs.sh` | Install system prerequisites |
| `install_requirements.sh` | Create venv and install Python packages |
| `build.sh` | Build C++/CUDA with CMake |
| `compile_manual.sh` | Manual compilation (CMake alternative) |
| `start_webapp.sh` | Start complete system |
| `start_worker.sh` | Start worker node |

---

## Directory Structure After Installation

```
CryptoPDC/
├── venv/                      # Python virtual environment
├── build/                     # CMake build output
│   ├── obj/                   # Object files
│   └── lib/                   # Libraries
├── logs/                      # Application logs
├── python/
│   └── cryptopdc/
│       └── bindings/
│           └── cryptopdc_bindings*.so  # Python bindings
└── scripts/
    ├── prereqs.sh
    ├── install_requirements.sh
    ├── build.sh
    ├── compile_manual.sh
    ├── start_webapp.sh
    └── start_worker.sh
```

---

## Getting Help

- **Documentation**: See `PROJECT_DOCUMENTATION.md`
- **Issues**: Report bugs on GitHub
- **Scripts Help**: Run any script with `--help`

```bash
./scripts/prereqs.sh --help
./scripts/install_requirements.sh --help
./scripts/build.sh --help
./scripts/start_webapp.sh --help
./scripts/start_worker.sh --help
```
