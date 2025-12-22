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

def result_handler(msg):
    """Handle results from workers"""
    task_id = msg.get('task_id')
    if task_id in tasks:
        tasks[task_id]['status'] = msg.get('status', 'completed')
        tasks[task_id]['result'] = msg.get('result', '')
        tasks[task_id]['duration'] = msg.get('duration', 0)
        tasks[task_id]['worker_id'] = msg.get('worker_id', '')
        tasks[task_id]['completed_at'] = datetime.now().isoformat()
        
        # Broadcast to all connected clients
        socketio.emit('task_update', tasks[task_id])

def init_infrastructure():
    """Initialize task queue and result collector"""
    global task_queue, result_collector
    
    if task_queue is None:
        task_queue = TaskQueue(port=5555)
        print("✓ Task Queue started on port 5555")
    
    if result_collector is None:
        result_collector = ResultCollector(port=5556, callback=result_handler)
        result_collector.start()
        print("✓ Result Collector started on port 5556")

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
            'gpu_supported': False
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
            'gpu_supported': False
        },
        {
            'id': 'aes128',
            'name': 'AES-128',
            'type': 'Symmetric',
            'output_size': '128-bit',
            'gpu_supported': False
        },
        {
            'id': 'des',
            'name': 'DES',
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
    data = request.json
    
    task_id = str(uuid.uuid4())
    
    # Get parameters
    charset = data.get('charset', 'abcdefghijklmnopqrstuvwxyz')
    min_len = data.get('min_length', 1)
    max_len = data.get('max_length', 6)
    attack_mode = data.get('attack_mode', 'brute')
    wordlist = data.get('wordlist', 'wordlist.txt')
    
    # Calculate total keyspace for all lengths
    total_keyspace = 0
    if attack_mode == 'brute':
        for length in range(min_len, max_len + 1):
            total_keyspace += len(charset) ** length
    else:
        # For dictionary or hybrid, keyspace is approximate or file size
        total_keyspace = 1000000 # dummy value
    
    task = {
        'task_id': task_id,
        'algorithm': data.get('algorithm'),
        'attack_mode': attack_mode,
        'target': data.get('target'),
        'status': 'queued',
        'submitted_at': datetime.now().isoformat(),
        'progress': 0,
        'result': None,
        'worker_id': None,
        'backend': 'GPU' if data.get('algorithm') in ['md5', 'sha256'] else 'CPU',
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
    
    tasks[task_id] = task
    
    # Push to queue
    task_queue.push(task)
    
    # Broadcast to clients
    socketio.emit('task_created', task)
    
    return jsonify(task), 201

@app.route('/api/tasks/<task_id>', methods=['GET'])
def get_task(task_id):
    """Get specific task"""
    if task_id not in tasks:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify(tasks[task_id])

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
    
    print("\n✓ Flask app starting on http://localhost:5000")
    print("  Open this URL in your browser\n")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
