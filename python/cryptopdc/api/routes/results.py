from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_results():
    return {"message": "Results endpoint"}
