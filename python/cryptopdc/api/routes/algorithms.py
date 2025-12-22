from fastapi import APIRouter
from typing import List, Dict

router = APIRouter()

@router.get("/")
async def list_algorithms() -> List[Dict]:
    return [
        {"name": "MD5", "type": "hash", "gpu_supported": True},
        {"name": "SHA-256", "type": "hash", "gpu_supported": True},
    ]
