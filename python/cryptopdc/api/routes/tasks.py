from fastapi import APIRouter, HTTPException, status
from typing import List
from cryptopdc.api.models.task import TaskRequest, TaskResponse, TaskDetail
from cryptopdc.distributed.master import MasterController

router = APIRouter()
master = MasterController()

@router.post("/", response_model=TaskResponse, status_code=status.HTTP_201_CREATED)
async def submit_task(request: TaskRequest):
    task_id = master.submit_task(request)
    task_data = master.get_task(task_id)
    return TaskResponse(
        task_id=task_id,
        status=task_data["status"],
        submitted_at=task_data["submitted_at"],
        algorithm=request.algorithm,
        target=request.target
    )

@router.get("/{task_id}", response_model=TaskDetail)
async def get_task(task_id: str):
    task_data = master.get_task(task_id)
    if not task_data:
        raise HTTPException(status_code=404, detail="Task not found")
        
    return TaskDetail(
        task_id=task_id,
        status=task_data["status"],
        submitted_at=task_data["submitted_at"],
        algorithm=task_data["request"].algorithm,
        target=task_data["request"].target,
        progress=task_data["progress"],
        result=task_data["result"],
        worker_count=len(task_data["workers"])
    )

@router.get("/", response_model=List[TaskResponse])
async def list_tasks():
    tasks = master.list_tasks()
    return [
        TaskResponse(
            task_id=t["id"],
            status=t["status"],
            submitted_at=t["submitted_at"],
            algorithm=t["request"].algorithm,
            target=t["request"].target
        )
        for t in tasks
    ]
