from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime

class TaskStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class AttackMode(str, Enum):
    BRUTE_FORCE = "brute_force"
    DICTIONARY = "dictionary"
    HYBRID = "hybrid"

class TaskRequest(BaseModel):
    algorithm: str = Field(..., example="md5")
    attack_mode: AttackMode = Field(..., example="brute_force")
    target: str = Field(..., example="5d41402abc4b2a76b9719d911017c592")
    options: Dict[str, Any] = Field(default_factory=dict, example={
        "charset": "abcdefghijklmnopqrstuvwxyz0123456789", 
        "min_length": 1, 
        "max_length": 6
    })

class TaskResponse(BaseModel):
    task_id: str
    status: TaskStatus
    submitted_at: datetime
    algorithm: str
    target: str

class TaskDetail(TaskResponse):
    progress: float = 0.0
    result: Optional[str] = None
    worker_count: int = 0
    stats: Dict[str, Any] = {}
    error: Optional[str] = None
