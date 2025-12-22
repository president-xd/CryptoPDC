# CryptoPDC Quick Start Guide

## 🚀 Running the System

### Option 1: Web Interface (Recommended)
```bash
# Start Flask web app + worker
./scripts/start_webapp.sh

# Open browser to http://localhost:5000
```

### Option 2: Command Line Demo
```bash
# Run the demo script
python3 scripts/run_demo.py
```

### Option 3: Manual Control
```bash
# Terminal 1: Start worker
python3 python/cryptopdc/distributed/worker.py

# Terminal 2: Use Python API
python3
>>> from cryptopdc.bindings import cryptopdc_bindings as core
>>> md5 = core.MD5()
>>> core.bytes_to_hex(md5.hash("hello"))
'5d41402abc4b2a76b9719d911017c592'
```

## 📁 Project Structure

```
crytoPDC/
├── core/                   # C++ Core Engine
├── cuda/                   # CUDA GPU Kernels
├── python/cryptopdc/       # Python Management Layer
├── webapp/                 # Flask Web Interface
├── scripts/                # Utility Scripts
└── build/                  # Compiled Binaries
```

## 🔧 Building from Source

```bash
# Compile C++/CUDA
./scripts/compile_manual.sh

# Install Python dependencies
pip install -r requirements.txt
```

## 🌐 Web Interface Features

- **Task Submission**: Select algorithm, enter hash, configure keyspace
- **Real-time Monitoring**: Live updates via WebSocket
- **Statistics Dashboard**: Track success rates and performance
- **Premium UI**: Dark theme with glassmorphism effects

## 📡 API Endpoints

- `GET /api/algorithms` - List supported algorithms
- `POST /api/tasks` - Submit new task
- `GET /api/tasks` - List all tasks
- `GET /api/tasks/<id>` - Get task status

## 🎯 Example: Crack MD5 Hash

**Via Web Interface:**
1. Select "MD5" algorithm
2. Enter hash: `5d41402abc4b2a76b9719d911017c592`
3. Set charset: "Lowercase (a-z)"
4. Set max length: 5
5. Click "Start Attack"
6. Watch real-time progress!

**Via Python:**
```python
from cryptopdc.bindings import cryptopdc_bindings as core

# GPU crack
found, result = core.cuda_crack_md5(
    "5d41402abc4b2a76b9719d911017c592",
    "abcdefghijklmnopqrstuvwxyz",
    5,  # key length
    0,  # start index
    12000000,  # count
    0   # device id
)

if found:
    print(f"Found: {result}")
```

## ⚡ Performance

- **MD5**: ~10+ GH/s on modern GPUs
- **SHA-256**: ~2+ GH/s on modern GPUs
- **Distributed**: Linear scaling with worker nodes

## 🔒 Legal Notice

This framework is for **authorized security research and educational purposes only**.
