import zmq
import sys
import os
import time
import json
import argparse
from typing import Dict, Any

# Ensure we can import bindings
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from cryptopdc.bindings import cryptopdc_bindings as core

class Worker:
    def __init__(self, master_ip="localhost", task_port=5555, result_port=5556, device_id=0):
        self.context = zmq.Context()
        
        # Pull tasks from master
        self.task_socket = self.context.socket(zmq.PULL)
        self.task_socket.connect(f"tcp://{master_ip}:{task_port}")
        
        # Push results to master
        self.result_socket = self.context.socket(zmq.PUSH)
        self.result_socket.connect(f"tcp://{master_ip}:{result_port}")
        
        # Subscribe to control messages (e.g. stop all)
        self.control_socket = self.context.socket(zmq.SUB)
        self.control_socket.connect(f"tcp://{master_ip}:{task_port+2}")
        self.control_socket.setsockopt_string(zmq.SUBSCRIBE, "")
        
        self.device_id = device_id
        self.poller = zmq.Poller()
        self.poller.register(self.task_socket, zmq.POLLIN)
        self.poller.register(self.control_socket, zmq.POLLIN)
        
        print(f"Worker initialized on Device {device_id}")

    def run(self):
        print("Waiting for tasks...")
        while True:
            socks = dict(self.poller.poll())
            
            if self.task_socket in socks and socks[self.task_socket] == zmq.POLLIN:
                task = self.task_socket.recv_json()
                self.process_task(task)
                
            if self.control_socket in socks and socks[self.control_socket] == zmq.POLLIN:
                msg = self.control_socket.recv_json()
                if msg.get("type") == "terminate":
                    print("Received termination signal.")
                    # In a real app we'd stop current processing
                    pass

    def process_task(self, task: Dict[str, Any]):
        print(f"Processing task {task.get('task_id')}...")
        try:
            algo = task.get('algorithm')
            target = task.get('target')
            attack_mode = task.get('attack_mode', 'brute')
            
            keyspace = task.get('keyspace', {})
            charset = keyspace.get('charset', 'abcdefghijklmnopqrstuvwxyz')
            min_length = keyspace.get('min_length', 1)
            max_length = keyspace.get('max_length', 5)
            
            if not target:
                print("Invalid task parameters")
                return

            found = False
            result = ""
            total_iterations = 0
            start_time = time.time()
            
            if attack_mode == 'dictionary':
                found, result, total_iterations = self.crack_dictionary(algo, target)
            else:
                # Brute Force: Iterate through lengths
                for length in range(min_length, max_length + 1):
                    if found: break
                    
                    print(f"Checking length {length}...")
                    iter_count = len(charset) ** length
                    
                    if algo == "md5":
                        # Use CUDA
                        found, result = core.cuda_crack_md5(
                            target, charset, length, 0, iter_count, self.device_id
                        )
                        total_iterations += iter_count
                    elif algo == "sha256":
                        if hasattr(core, 'cuda_crack_sha256'):
                             found, result = core.cuda_crack_sha256(
                                target, charset, length, 0, iter_count, self.device_id
                            )
                             total_iterations += iter_count
                        else:
                            f, r, c = self.crack_cpu(algo, target, charset, length, 0, iter_count)
                            total_iterations += c
                            if f:
                                found = True
                                result = r
                    else:
                        # CPU Fallback
                        f, r, c = self.crack_cpu(algo, target, charset, length, 0, iter_count)
                        total_iterations += c
                        if f:
                            found = True
                            result = r

            duration = time.time() - start_time
            
            if found:
                print(f"SUCCESS: Found key '{result}'")
                self.result_socket.send_json({
                    "type": "result",
                    "task_id": task['task_id'],
                    "status": "found",
                    "result": result,
                    "worker_id": f"gpu-{self.device_id}",
                    "duration": duration,
                    "iterations": total_iterations
                })
            else:
                print(f"Not found in {total_iterations} iterations ({duration:.2f}s)")
                self.result_socket.send_json({
                    "type": "result",
                    "task_id": task['task_id'],
                    "status": "completed",
                    "result": None,
                    "worker_id": f"gpu-{self.device_id}",
                    "duration": duration,
                    "iterations": total_iterations
                })
                
        except Exception as e:
            print(f"Task processing error: {e}")
            import traceback
            traceback.print_exc()
            self.result_socket.send_json({
                "type": "error",
                "task_id": task.get('task_id'),
                "error": str(e)
            })

    def crack_cpu(self, algo, target, charset, max_val, start, count):
        """CPU Brute Force Fallback"""
        import hashlib
        
        # Select hash function
        hash_func = None
        if algo == 'md5': hash_func = hashlib.md5
        elif algo == 'sha1': hash_func = hashlib.sha1
        elif algo == 'sha256': hash_func = hashlib.sha256
        elif algo == 'sha512': hash_func = hashlib.sha512
        else:
            print(f"Algorithm {algo} not supported on CPU yet")
            return False, "", 0
            
        print(f"Starting CPU crack for {algo} ({count} keys)...")
        
        # Simple loop for demonstration - optimized batching would be better
        # We need to map index to key. We can use core.index_to_key if available/fast,
        # otherwise python implementation. Using core binding is better.
        
        for i in range(count):
            current_idx = start + i
            # Use binding to generate key
            try:
                # We need to calculate length for this index. 
                # Simplifying: assume max_len for all for now or check ranges.
                # Actually, core.index_to_key needs fixed length.
                # For mixed lengths, we'd need loop over lengths.
                # For this demo, we'll try to generate key at max_length.
                # A proper implementation handles length ranges.
                
                # Using a simple python iterator for correctness in fallback
                key = core.index_to_key(current_idx, charset, max_val)
            except:
                continue

            h = hash_func(key.encode()).hexdigest()
            if h == target:
                return True, key, i+1
                
            if i % 100000 == 0 and i > 0:
                print(f"CPU Progress: {i}/{count}")
                
        return False, "", count

    def crack_dictionary(self, algo, target):
        """Dictionary Attack"""
        import hashlib
        
        # Use absolute path to ensure we find the wordlist
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        wordlist_path = os.path.join(base_dir, "wordlist.txt")
        
        print(f"Starting Dictionary attack for {algo} using {wordlist_path}...")
        
        if not os.path.exists(wordlist_path):
            print(f"Wordlist not found at {wordlist_path}!")
            return False, "", 0
            
        hash_func = None
        try:
            if algo == 'md5': hash_func = hashlib.md5
            elif algo == 'sha1': hash_func = hashlib.sha1
            elif algo == 'sha256': hash_func = hashlib.sha256
            elif algo == 'sha512': hash_func = hashlib.sha512
            else:
                print(f"Algorithm {algo} not supported for dictionary")
                return False, "", 0
        except Exception as e:
             print(f"Error initializing hash function: {e}")
             return False, "", 0
            
        count = 0
        found = False
        result_key = ""
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if not word: continue
                    
                    count += 1
                    try:
                        h = hash_func(word.encode()).hexdigest()
                        if h == target:
                            print(f"Dictionary matched: {word}")
                            found = True
                            result_key = word
                            break
                    except Exception as loop_e:
                        continue
                        
        except Exception as e:
            print(f"Dictionary error: {e}")
            import traceback
            traceback.print_exc()
            
        return found, result_key, count

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--master", default="localhost", help="Master IP")
    parser.add_argument("--device", type=int, default=0, help="GPU Device ID")
    args = parser.parse_args()
    
    worker = Worker(master_ip=args.master, device_id=args.device)
    worker.run()
