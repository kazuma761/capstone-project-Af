from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends, Header
from pydantic import BaseModel
from typing import Optional
from jose import JWTError, jwt
from config import get_settings
from services.scanner_router import ScannerRouter
from services.message_scanner import message_scanner
from services.websocket_manager import manager
from database import get_db
import asyncio

router = APIRouter()
settings = get_settings()
scanner = ScannerRouter()

class URLScanRequest(BaseModel):
    url: str

class MessageScanRequest(BaseModel):
    message: str

async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.post("/url")
async def scan_url(request: URLScanRequest, user_id: str = Depends(get_current_user), db = Depends(get_db)):
    scan_record = await db.scan.create(
        data={
            "userId": user_id,
            "scanType": "url",
            "target": request.url,
            "status": "pending"
        }
    )
    
    asyncio.create_task(scanner.scan_url(request.url, scan_record.id, user_id))
    return {"scan_id": scan_record.id, "status": "started"}

@router.post("/pdf")
async def scan_pdf(file: UploadFile = File(...), user_id: str = Depends(get_current_user), db = Depends(get_db)):
    contents = await file.read()
    
    scan_record = await db.scan.create(
        data={
            "userId": user_id,
            "scanType": "pdf",
            "target": file.filename,
            "status": "pending"
        }
    )
    
    asyncio.create_task(scanner.scan_pdf(contents, file.filename, scan_record.id, user_id))
    return {"scan_id": scan_record.id, "status": "started"}

@router.post("/file")
async def scan_file(file: UploadFile = File(...), user_id: str = Depends(get_current_user), db = Depends(get_db)):
    contents = await file.read()
    
    scan_record = await db.scan.create(
        data={
            "userId": user_id,
            "scanType": "file",
            "target": file.filename,
            "status": "pending"
        }
    )
    
    asyncio.create_task(scanner.scan_file(contents, file.filename, scan_record.id, user_id))
    return {"scan_id": scan_record.id, "status": "started"}

@router.post("/image")
async def scan_image(file: UploadFile = File(...), user_id: str = Depends(get_current_user), db = Depends(get_db)):
    contents = await file.read()
    
    scan_record = await db.scan.create(
        data={
            "userId": user_id,
            "scanType": "image",
            "target": file.filename,
            "status": "pending"
        }
    )
    
    asyncio.create_task(scanner.scan_image(contents, file.filename, scan_record.id, user_id))
    return {"scan_id": scan_record.id, "status": "started"}

@router.get("/history")
async def get_scan_history(user_id: str = Depends(get_current_user), db = Depends(get_db)):
    scans = await db.scan.find_many(
        where={"userId": user_id},
        order={"createdAt": "desc"},
        take=50
    )
    return scans

@router.get("/{scan_id}")
async def get_scan_result(scan_id: str, user_id: str = Depends(get_current_user), db = Depends(get_db)):
    scan = await db.scan.find_unique(where={"id": scan_id})
    if not scan or scan.userId != user_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.post("/message")
async def scan_message(request: MessageScanRequest, user_id: str = Depends(get_current_user), db = Depends(get_db)):
    """Analyze a message for scam/phishing indicators"""
    
    # Create scan record
    scan_record = await db.scan.create(
        data={
            "userId": user_id,
            "scanType": "message",
            "target": request.message[:100] + "..." if len(request.message) > 100 else request.message,
            "status": "scanning"
        }
    )
    
    # Send progress update
    await manager.send_message(user_id, {
        "scan_id": scan_record.id,
        "status": "scanning",
        "progress": 30,
        "message": "Analyzing message for scam indicators..."
    })
    
    # Analyze message
    result = await message_scanner.analyze_message(request.message)
    
    # Determine threat level from verdict
    threat_level_map = {
        "scam": "high",
        "suspicious": "medium",
        "potentially_suspicious": "low",
        "likely_safe": "clean"
    }
    threat_level = threat_level_map.get(result.get("verdict"), "clean")
    
    # Update scan record
    import json
    from datetime import datetime
    await db.scan.update(
        where={"id": scan_record.id},
        data={
            "status": "completed",
            "result": json.dumps(result),
            "threatLevel": threat_level,
            "endTime": datetime.utcnow()
        }
    )
    
    # Send completion
    await manager.send_message(user_id, {
        "scan_id": scan_record.id,
        "status": "completed",
        "progress": 100,
        "result": result,
        "threat_level": threat_level
    })
    
    return {"scan_id": scan_record.id, "status": "completed", "result": result}
