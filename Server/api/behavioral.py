"""
Behavioral Monitor API Routes
APSA-based real-time process monitoring endpoints
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Optional
from services.behavioral_monitor import behavioral_monitor
from services.websocket_manager import manager
from api.auth import get_current_user

router = APIRouter()


@router.post("/start")
async def start_monitoring(current_user: dict = Depends(get_current_user)):
    """Start the APSA behavioral monitor"""
    # Wire up WebSocket broadcasting for real-time updates
    behavioral_monitor.websocket_callback = manager.broadcast
    
    result = await behavioral_monitor.start()
    return {
        "message": "Behavioral monitor started" if result["status"] == "started" else "Monitor already running",
        **result
    }


@router.post("/stop")
async def stop_monitoring(current_user: dict = Depends(get_current_user)):
    """Stop the APSA behavioral monitor"""
    result = await behavioral_monitor.stop()
    return {
        "message": "Behavioral monitor stopped",
        **result
    }


@router.get("/status")
async def get_status(current_user: dict = Depends(get_current_user)):
    """Get current monitor status"""
    return behavioral_monitor.get_status()


@router.get("/processes")
async def get_processes(
    tier: Optional[str] = Query(None, description="Filter by tier: CLEAN, MONITOR, SUSPICIOUS, ALERT"),
    current_user: dict = Depends(get_current_user)
):
    """Get list of monitored processes with risk scores"""
    processes = behavioral_monitor.get_processes(tier_filter=tier)
    return {
        "processes": processes,
        "total": len(processes)
    }


@router.get("/alerts")
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    current_user: dict = Depends(get_current_user)
):
    """Get recent behavioral alerts"""
    alerts = behavioral_monitor.get_alerts(limit=limit)
    return {
        "alerts": alerts,
        "total": len(alerts)
    }


@router.get("/baseline/{process_name}")
async def get_baseline(
    process_name: str,
    current_user: dict = Depends(get_current_user)
):
    """Get adaptive baseline for a specific process"""
    baseline = behavioral_monitor.get_baseline(process_name)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found for this process")
    return {
        "process_name": process_name,
        "baseline": baseline
    }


@router.post("/kill/{pid}")
async def kill_process(
    pid: int,
    current_user: dict = Depends(get_current_user)
):
    """Kill a suspicious process by PID"""
    result = await behavioral_monitor.kill_process(pid)
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result


@router.get("/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    """Get behavioral monitoring statistics"""
    status = behavioral_monitor.get_status()
    processes = behavioral_monitor.get_processes()
    
    tier_counts = {
        "CLEAN": 0,
        "MONITOR": 0,
        "SUSPICIOUS": 0,
        "ALERT": 0
    }
    
    for proc in processes:
        tier = proc.get("tier", "CLEAN")
        if tier in tier_counts:
            tier_counts[tier] += 1
    
    # Calculate average risk score
    risk_scores = [p.get("risk_score", 0) for p in processes]
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    
    return {
        "is_running": status["is_running"],
        "total_processes": len(processes),
        "tier_distribution": tier_counts,
        "average_risk_score": round(avg_risk, 4),
        "total_alerts": status["alert_count"]
    }
