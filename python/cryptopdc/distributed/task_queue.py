import zmq
import json
import threading

class TaskQueue:
    def __init__(self, port=5555):
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUSH)
        self.socket.bind(f"tcp://*:{port}")
        
    def push(self, task):
        self.socket.send_json(task)

class ResultCollector:
    def __init__(self, port=5556, callback=None):
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PULL)
        self.socket.bind(f"tcp://*:{port}")
        self.callback = callback
        self.running = True
        self.thread = threading.Thread(target=self._loop)
        
    def start(self):
        self.thread.start()
        
    def _loop(self):
        while self.running:
            try:
                # Non-blocking check or allow timeout
                # for simplicity using blocking
                msg = self.socket.recv_json()
                if self.callback:
                    self.callback(msg)
            except Exception as e:
                print(f"Result collector error: {e}")
                
    def stop(self):
        self.running = False
        # self.context.term() # Cleanup
