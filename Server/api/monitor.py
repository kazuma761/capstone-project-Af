from fastapi import APIRouter, Depends
from services.folder_monitor import folder_monitor
from api.scan import get_current_user

router = APIRouter()

@router.post("/start")
async def start_monitoring(user_id: str = Depends(get_current_user)):
    """Start monitoring download folder"""
    folder_monitor.start_monitoring(user_id)
    return {"status": "started", "message": "Download folder monitoring started"}

@router.post("/stop")
async def stop_monitoring(user_id: str = Depends(get_current_user)):
    """Stop monitoring download folder"""
    folder_monitor.stop_monitoring(user_id)
    return {"status": "stopped", "message": "Download folder monitoring stopped"}

@router.get("/status")
async def get_monitoring_status(user_id: str = Depends(get_current_user)):
    """Check if monitoring is active"""
    is_active = user_id in folder_monitor.observers
    return {"is_active": is_active}
