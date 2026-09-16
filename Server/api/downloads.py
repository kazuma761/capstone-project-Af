from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from pathlib import Path
import os
from api.scan import get_current_user
from services.clamav_scanner import ClamAVScanner
from services.websocket_manager import manager
from database import db

router = APIRouter()

class ScanRequest(BaseModel):
    file_path: str

def get_downloads_folder():
    """Get the user's Downloads folder path"""
    return str(Path.home() / "Downloads")

@router.get("/list")
async def list_downloads(user_id: str = Depends(get_current_user)):
    """List all files in the Downloads folder"""
    try:
        downloads_path = get_downloads_folder()
        
        if not os.path.exists(downloads_path):
            return {"files": []}
        
        files = []
        for filename in os.listdir(downloads_path):
            file_path = os.path.join(downloads_path, filename)
            
            # Skip directories and hidden files
            if os.path.isdir(file_path) or filename.startswith('.'):
                continue
            
            try:
                stat = os.stat(file_path)
                files.append({
                    "name": filename,
                    "path": file_path,
                    "size": stat.st_size,
                    "modified": int(stat.st_mtime * 1000)  # Convert to milliseconds
                })
            except Exception as e:
                print(f"Error getting file info for {filename}: {e}")
                continue
        
        # Sort by modified time (newest first)
        files.sort(key=lambda x: x["modified"], reverse=True)
        
        return {"files": files}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan")
async def scan_download_file(
    request: ScanRequest,
    user_id: str = Depends(get_current_user)
):
    """Scan a specific file from Downloads folder using ClamAV"""
    try:
        file_path = request.file_path
        
        # Security check: ensure file is in Downloads folder
        downloads_path = get_downloads_folder()
        if not file_path.startswith(downloads_path):
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="File not found")
        
        filename = os.path.basename(file_path)
        
        # Create scan record
        scan_record = await db.scan.create(
            data={
                "userId": user_id,
                "scanType": "file",
                "target": filename,
                "status": "pending"
            }
        )
        
        # Read file content
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        # Scan with ClamAV
        scanner = ClamAVScanner()
        result = await scanner.scan_file(file_content, filename)
        
        print(f"Scan result: {result}")
        
        # Determine threat level
        is_clean = result.get("is_clean", True)
        threat_level = "clean" if is_clean else "high"
        
        # Update scan record
        try:
            import json
            await db.scan.update(
                where={"id": scan_record.id},
                data={
                    "status": "completed",
                    "threatLevel": threat_level,
                    "result": json.dumps(result)  # Convert dict to JSON string
                }
            )
            print("Database updated successfully")
        except Exception as db_error:
            print(f"Database update error: {db_error}")
            # Continue even if DB update fails
        
        # Send WebSocket notification
        try:
            await manager.send_message(user_id, {
                "type": "scan_completed",
                "scan_id": scan_record.id,
                "file_path": file_path,
                "filename": filename,
                "threats_found": 0 if is_clean else 1,
                "threat_level": threat_level,
                "result": result
            })
            print("WebSocket notification sent")
        except Exception as ws_error:
            print(f"WebSocket error: {ws_error}")
            # Continue even if WebSocket fails
        
        return {
            "scan_id": scan_record.id,
            "status": "completed",
            "result": result
        }
    
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Scan error: {e}")
        print(f"Full traceback:\n{error_details}")
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")
