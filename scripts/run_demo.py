import sys
import os
import time
import subprocess
import signal

# Ensure python path
sys.path.append(os.path.join(os.getcwd(), 'python'))

from cryptopdc.distributed.task_queue import TaskQueue, ResultCollector
from cryptopdc.bindings import cryptopdc_bindings as core

def result_handler(msg):
    print("\n" + "="*50)
    print(f"RECEIVED RESULT from {msg.get('worker_id')}")
    print(f"Status: {msg.get('status')}")
    print(f"Result: {msg.get('result')}")
    print(f"Duration: {msg.get('duration'):.4f}s")
    print("="*50 + "\n")
    # Terminate demo
    os._exit(0)

def main():
    print("Starting CryptoPDC Demo...")
    
    # Generate a target hash (MD5 of 'abcde')
    # Using local binding to generate target
    md5 = core.MD5()
    target_hash = core.bytes_to_hex(md5.hash("abcde"))
    print(f"Target Hash: {target_hash} (MD5 of 'abcde')")
    
    # Start Collector
    collector = ResultCollector(callback=result_handler)
    collector.start()
    print("Result Collector started on port 5556")
    
    # Start Task Queue
    queue = TaskQueue(port=5555)
    print("Task Queue started on port 5555")
    
    # Start Worker Process
    print("Launching Worker...")
    worker_env = os.environ.copy()
    worker_env["PYTHONPATH"] = os.path.join(os.getcwd(), 'python')
    
    worker_proc = subprocess.Popen(
        [sys.executable, "python/cryptopdc/distributed/worker.py"],
        env=worker_env,
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    
    time.sleep(2) # Give worker time to start
    
    # Create Task
    task = {
        "task_id": "demo-task-001",
        "algorithm": "md5",
        "target": target_hash,
        "keyspace": {
            "charset": "abcdefghijklmnopqrstuvwxyz",
            "length": 5,
            "start": 0,
            "end": 12000000 # Coverage sufficient for 5 chars
        }
    }
    
    print(f"Submitting task: Crack {target_hash}")
    queue.push(task)
    
    print("Task submitted. Waiting for result...")
    
    try:
        worker_proc.wait()
    except KeyboardInterrupt:
        print("Stopping...")
        worker_proc.terminate()
        collector.stop()

if __name__ == "__main__":
    main()
