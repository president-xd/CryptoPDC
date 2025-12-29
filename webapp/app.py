from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import sys
import os
import threading
import time
import uuid
from datetime import datetime

# Add python directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'python'))

from cryptopdc.distributed.task_queue import TaskQueue, ResultCollector
from cryptopdc.bindings import cryptopdc_bindings as core

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cryptopdc-secret-key-2024'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
tasks = {}
task_queue = None
result_collector = None
local_worker_thread = None

def result_handler(msg):
    """Handle results from workers"""
    task_id = msg.get('task_id')
    msg_type = msg.get('type', 'result')
    print(f"Result received for task {task_id}: type={msg_type}, status={msg.get('status')}")
    
    if task_id in tasks:
        # Handle error messages
        if msg_type == 'error':
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['error'] = msg.get('error', 'Unknown error')
        else:
            tasks[task_id]['status'] = msg.get('status', 'completed')
            tasks[task_id]['result'] = msg.get('result', '')
        
        tasks[task_id]['duration'] = msg.get('duration', 0)
        tasks[task_id]['iterations'] = msg.get('iterations', 0)
        tasks[task_id]['worker_id'] = msg.get('worker_id', '')
        tasks[task_id]['completed_at'] = datetime.now().isoformat()
        
        # Broadcast to all connected clients (use socketio.emit with namespace for background thread)
        socketio.emit('task_update', tasks[task_id], namespace='/')
        print(f"Emitted task_update for {task_id}")

def generate_candidates(charset, length, batch_size=100000):
    """Generate candidate keys for brute force"""
    from itertools import product
    candidates = []
    for combo in product(charset, repeat=length):
        candidates.append(''.join(combo))
        if len(candidates) >= batch_size:
            yield candidates
            candidates = []
    if candidates:
        yield candidates

def generate_aes_key_candidates(charset, length, key_bytes, batch_size=50000):
    """Generate AES key candidates - converts password to padded hex key"""
    from itertools import product
    candidates = []
    for combo in product(charset, repeat=length):
        password = ''.join(combo)
        # Convert password to bytes and pad to key_bytes
        key_bytes_data = password.encode('utf-8')
        # Pad with zeros to reach required key length
        if len(key_bytes_data) < key_bytes:
            key_bytes_data = key_bytes_data + b'\x00' * (key_bytes - len(key_bytes_data))
        key_hex = key_bytes_data[:key_bytes].hex()
        candidates.append(key_hex)
        if len(candidates) >= batch_size:
            yield candidates
            candidates = []
    if candidates:
        yield candidates

def process_task_locally(task):
    """Process a task locally using the C++ bindings"""
    task_id = task.get('task_id')
    algo = task.get('algorithm')
    target = task.get('target')  # For hash: hash to crack; For AES: ciphertext
    attack_mode = task.get('attack_mode', 'brute')
    backend = task.get('backend_selection', 'auto')
    
    keyspace = task.get('keyspace', {})
    charset = keyspace.get('charset', 'abcdefghijklmnopqrstuvwxyz')
    min_length = keyspace.get('min_length', 1)
    max_length = keyspace.get('max_length', 6)
    wordlist = keyspace.get('wordlist', 'wordlist.txt')
    
    # AES specific params
    aes_key_size = task.get('aes_key_size', 128)
    plaintext = task.get('plaintext', '')  # Known plaintext for AES attack
    
    print(f"Local worker processing task {task_id}: {algo} {attack_mode}")
    
    # Update status to running
    if task_id in tasks:
        tasks[task_id]['status'] = 'running'
        socketio.emit('task_update', tasks[task_id], namespace='/')
    
    start_time = time.time()
    found = False
    result = ""
    total_iterations = 0
    
    try:
        if algo == 'aes':
            # AES key cracking - requires both plaintext and ciphertext
            if not plaintext:
                raise ValueError("AES cracking requires known plaintext. This is a known-plaintext attack.")
            
            ciphertext = target.lower()  # Normalize to lowercase
            plaintext = plaintext.lower()
            key_bytes = aes_key_size // 8  # 16, 24, or 32 bytes
            
            print(f"  AES-{aes_key_size} known-plaintext attack")
            print(f"  Plaintext (hex): {plaintext}")
            print(f"  Ciphertext (hex): {ciphertext}")
            print(f"  Key size: {key_bytes} bytes ({key_bytes * 2} hex chars)")
            
            # For AES, we generate candidate passwords, convert to keys and test them
            for length in range(min_length, max_length + 1):
                if found:
                    break
                
                iter_count = len(charset) ** length
                print(f"  Trying password length {length} ({iter_count} combinations)...")
                
                # Generate candidates in batches using the AES-specific generator
                batch_count = 0
                for batch in generate_aes_key_candidates(charset, length, key_bytes, batch_size=50000):
                    if found:
                        break
                    
                    batch_count += 1
                    if batch_count % 10 == 0:
                        print(f"    Processed {total_iterations + len(batch)} candidates...")
                    
                    try:
                        if aes_key_size == 128:
                            found_key = core.cuda_crack_aes128(plaintext, ciphertext, batch)
                        elif aes_key_size == 192:
                            found_key = core.cuda_crack_aes192(plaintext, ciphertext, batch)
                        else:
                            found_key = core.cuda_crack_aes256(plaintext, ciphertext, batch)
                        
                        if found_key:
                            found = True
                            # Convert hex key back to original password (strip null padding)
                            key_data = bytes.fromhex(found_key)
                            result = key_data.rstrip(b'\x00').decode('utf-8', errors='replace')
                            print(f"  *** FOUND KEY: '{result}' (hex: {found_key}) ***")
                            break
                    except Exception as e:
                        print(f"  AES crack error: {e}")
                        import traceback
                        traceback.print_exc()
                    
                    total_iterations += len(batch)
                    
        elif attack_mode == 'dictionary':
            # Dictionary attack using CPU
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            wordlist_path = os.path.join(base_dir, 'wordlists', wordlist)
            if not os.path.exists(wordlist_path):
                wordlist_path = os.path.join(base_dir, wordlist)
            
            print(f"Dictionary attack using: {wordlist_path}")
            found, result, total_iterations = core.crack_dictionary(algo, target, wordlist_path)
        else:
            # Brute force attack for hash algorithms
            gpu_algos = ['md5', 'sha1', 'sha256', 'sha512']
            use_gpu = (backend == 'gpu' or (backend == 'auto' and algo in gpu_algos)) and backend != 'cpu'
            
            for length in range(min_length, max_length + 1):
                if found:
                    break
                    
                iter_count = len(charset) ** length
                print(f"  Trying length {length} ({iter_count} combinations)...")
                
                if use_gpu and algo == 'md5' and hasattr(core, 'cuda_crack_md5'):
                    found, result = core.cuda_crack_md5(target, charset, length, 0, iter_count, 0)
                elif use_gpu and algo == 'sha1' and hasattr(core, 'cuda_crack_sha1'):
                    found, result = core.cuda_crack_sha1(target, charset, length, 0, iter_count, 0)
                elif use_gpu and algo == 'sha256' and hasattr(core, 'cuda_crack_sha256'):
                    found, result = core.cuda_crack_sha256(target, charset, length, 0, iter_count, 0)
                elif use_gpu and algo == 'sha512' and hasattr(core, 'cuda_crack_sha512'):
                    found, result = core.cuda_crack_sha512(target, charset, length, 0, iter_count, 0)
                else:
                    # CPU fallback
                    print(f"  Using CPU mode for {algo}")
                    pass
                
                total_iterations += iter_count
        
        duration = time.time() - start_time
        status = 'found' if found else 'completed'
        
        print(f"Task {task_id} {status}: result='{result}' in {duration:.2f}s")
        
        # Update task
        if task_id in tasks:
            tasks[task_id]['status'] = status
            tasks[task_id]['result'] = result if found else None
            tasks[task_id]['duration'] = duration
            tasks[task_id]['iterations'] = total_iterations
            tasks[task_id]['worker_id'] = 'local'
            tasks[task_id]['completed_at'] = datetime.now().isoformat()
            socketio.emit('task_update', tasks[task_id], namespace='/')
            
    except Exception as e:
        print(f"Error processing task {task_id}: {e}")
        if task_id in tasks:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['error'] = str(e)
            socketio.emit('task_update', tasks[task_id], namespace='/')

def init_infrastructure():
    """Initialize task queue and result collector"""
    global task_queue, result_collector
    
    if task_queue is None:
        task_queue = TaskQueue(port=5555)
        print("[OK] Task Queue started on port 5555")
    
    if result_collector is None:
        result_collector = ResultCollector(port=5556, callback=result_handler)
        result_collector.start()
        print("[OK] Result Collector started on port 5556")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/algorithms', methods=['GET'])
def get_algorithms():
    """Get list of supported algorithms"""
    return jsonify([
        {
            'id': 'md5',
            'name': 'MD5',
            'type': 'Hash',
            'output_size': '128-bit',
            'gpu_supported': True
        },
        {
            'id': 'sha1',
            'name': 'SHA-1',
            'type': 'Hash',
            'output_size': '160-bit',
            'gpu_supported': True
        },
        {
            'id': 'sha256',
            'name': 'SHA-256',
            'type': 'Hash',
            'output_size': '256-bit',
            'gpu_supported': True
        },
        {
            'id': 'sha512',
            'name': 'SHA-512',
            'type': 'Hash',
            'output_size': '512-bit',
            'gpu_supported': True
        },
        {
            'id': 'aes',
            'name': 'AES',
            'type': 'Symmetric',
            'output_size': '128/192/256-bit',
            'gpu_supported': True,
            'key_sizes': [128, 192, 256]
        },
        {
            'id': 'des',
            'name': 'DES',
            'type': 'Symmetric',
            'output_size': '64-bit',
            'gpu_supported': False
        },
        {
            'id': '3des',
            'name': '3DES',
            'type': 'Symmetric',
            'output_size': '64-bit',
            'gpu_supported': False
        }
    ])

@app.route('/api/wordlists', methods=['GET'])
def get_wordlists():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    wordlists_dir = os.path.join(os.path.dirname(base_dir), 'wordlists')
    
    lists = []
    # Add default
    lists.append({'id': 'wordlist.txt', 'name': 'Default Wordlist'})
    
    if os.path.exists(wordlists_dir):
        for f in os.listdir(wordlists_dir):
            if f.endswith('.txt'):
                lists.append({'id': f, 'name': f})
    
    return jsonify(lists)

@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    """Get all tasks"""
    return jsonify(list(tasks.values()))

@app.route('/api/tasks', methods=['POST'])
def submit_task():
    """Submit a new cracking task"""
    print("=== SUBMIT_TASK CALLED ===")
    print(f"Request method: {request.method}")
    print(f"Request data: {request.data}")
    data = request.json
    print(f"Parsed JSON: {data}")
    
    task_id = str(uuid.uuid4())
    
    # Get parameters
    charset = data.get('charset', 'abcdefghijklmnopqrstuvwxyz')
    min_len = data.get('min_length', 1)
    max_len = data.get('max_length', 6)
    attack_mode = data.get('attack_mode', 'brute')
    wordlist = data.get('wordlist', 'wordlist.txt')
    backend_selection = data.get('backend', 'auto')
    
    # Algorithm-specific parameters
    algorithm = data.get('algorithm')
    aes_key_size = data.get('aes_key_size', 128)
    cipher_mode = data.get('cipher_mode', 'ecb')
    padding = data.get('padding', 'none')
    
    # Knowledge states for symmetric encryption
    key_knowledge = data.get('key_knowledge', 'unknown')
    iv_knowledge = data.get('iv_knowledge', 'known')
    plaintext_knowledge = data.get('plaintext_knowledge', 'known')
    
    # Known values
    aes_key = data.get('aes_key', '')
    aes_iv = data.get('aes_iv', '')
    aes_plaintext = data.get('aes_plaintext', '')
    
    # Calculate total keyspace for all lengths
    total_keyspace = 0
    if attack_mode == 'brute':
        for length in range(min_len, max_len + 1):
            total_keyspace += len(charset) ** length
    else:
        total_keyspace = 1000000
    
    # Determine algorithm name with key size for AES
    algorithm_display = algorithm
    if algorithm and algorithm.lower() == 'aes':
        algorithm_display = f"AES-{aes_key_size}"
    
    # Determine backend based on user selection and algorithm support
    gpu_supported_algos = ['md5', 'sha1', 'sha256', 'sha512', 'aes']
    print(f"DEBUG: backend_selection={backend_selection}, algorithm={algorithm}")
    
    if backend_selection == 'gpu':
        backend_display = 'GPU'
    elif backend_selection == 'cpu':
        backend_display = 'CPU'
    else:
        backend_display = 'GPU' if algorithm in gpu_supported_algos else 'CPU'
    print(f"DEBUG: backend_display={backend_display}")
    
    task = {
        'task_id': task_id,
        'algorithm': algorithm,
        'algorithm_display': algorithm_display,
        'attack_mode': attack_mode,
        'target': data.get('target'),
        'status': 'queued',
        'submitted_at': datetime.now().isoformat(),
        'progress': 0,
        'result': None,
        'worker_id': None,
        'backend': backend_display,
        'backend_selection': backend_selection,
        'keyspace': {
            'charset': charset,
            'min_length': min_len,
            'max_length': max_len,
            'start': 0,
            'end': total_keyspace,
            'total': total_keyspace,
            'wordlist': wordlist
        }
    }
    
    # Add symmetric encryption specific fields
    if algorithm and algorithm.lower() in ['aes', 'des', '3des']:
        task['aes_key_size'] = aes_key_size
        task['cipher_mode'] = cipher_mode
        task['padding'] = padding
        task['key_knowledge'] = key_knowledge
        task['iv_knowledge'] = iv_knowledge
        task['plaintext_knowledge'] = plaintext_knowledge
        
        # Add known values if provided
        if key_knowledge == 'known' and aes_key:
            task['aes_key'] = aes_key
        if iv_knowledge == 'known' and aes_iv:
            task['aes_iv'] = aes_iv
        if plaintext_knowledge == 'known' and aes_plaintext:
            task['plaintext'] = aes_plaintext
    
    tasks[task_id] = task
    
    # Broadcast to clients that task was created
    socketio.emit('task_created', task)
    
    # Process task locally in a background thread
    worker_thread = threading.Thread(target=process_task_locally, args=(task,))
    worker_thread.daemon = True
    worker_thread.start()
    
    return jsonify(task), 201

@app.route('/api/tasks/<task_id>', methods=['GET'])
def get_task(task_id):
    """Get specific task"""
    if task_id not in tasks:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify(tasks[task_id])

@app.route('/api/tasks/<task_id>', methods=['DELETE'])
def cancel_task(task_id):
    """Cancel a task by ID"""
    if task_id not in tasks:
        return jsonify({'error': 'Task not found'}), 404
    
    task = tasks[task_id]
    
    # Only allow canceling tasks that are not already completed
    if task['status'] in ['found', 'completed', 'cancelled']:
        return jsonify({'error': f"Task already {task['status']}"}), 400
    
    # Update task status
    task['status'] = 'cancelled'
    task['cancelled_at'] = datetime.now().isoformat()
    
    # Broadcast cancellation to all clients
    socketio.emit('task_update', task, namespace='/')
    
    # TODO: Send cancel signal to worker via control socket
    
    return jsonify({'message': 'Task cancelled', 'task': task}), 200

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connection_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  CryptoPDC Web Interface")
    print("="*60)
    
    init_infrastructure()
    
    print("\n[OK] Flask app starting on http://localhost:5000")
    print("  Open this URL in your browser\n")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
