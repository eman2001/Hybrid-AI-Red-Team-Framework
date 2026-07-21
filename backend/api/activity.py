from fastapi import APIRouter

from backend.storage.activity_store import get_activities


router = APIRouter(
    prefix="/api/activity",
    tags=["Activity"]
)



@router.get("/")
def activity_feed():

    return get_activities()
