import uuid
import asyncio
from typing import Dict, Optional, List
from datetime import datetime
from cryptopdc.api.models.task import TaskRequest, TaskStatus, TaskDetail

class MasterController:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MasterController, cls).__new__(cls)
            cls._instance.tasks = {}
            cls._instance.workers = {}
        return cls._instance

    def submit_task(self, request: TaskRequest) -> str:
        task_id = str(uuid.uuid4())
        self.tasks[task_id] = {
            "id": task_id,
            "request": request,
            "status": TaskStatus.QUEUED,
            "submitted_at": datetime.now(),
            "progress": 0.0,
            "result": None,
            "workers": []
        }
        # In a real system, verify algorithm support here
        # Trigger distribution logic
        asyncio.create_task(self._process_task(task_id))
        return task_id

    def get_task(self, task_id: str) -> Optional[Dict]:
        return self.tasks.get(task_id)

    def list_tasks(self) -> List[Dict]:
        return list(self.tasks.values())
        
    async def _process_task(self, task_id: str):
        # Mock processing for now until workers are connected
        task = self.tasks[task_id]
        print(f"Processing task {task_id} locally/distributing...")
        task["status"] = TaskStatus.RUNNING
        
        # Here we would dispatch to ZeroMQ
        # For demonstration, we could call the local binding if available
        # But we'll leave that for the worker logic
