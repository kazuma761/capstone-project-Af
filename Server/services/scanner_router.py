from datetime import datetime
import json
from services.websocket_manager import manager
from services.url_scanner import URLScanner
from services.virustotal import VirusTotal
from services.clamav_scanner import ClamAVScanner
from services.image_scanner import ImageScanner
from database import db

class ScannerRouter:
    def __init__(self):
        self.url_scanner = URLScanner()
        self.virustotal = VirusTotal()
        self.clamav = ClamAVScanner()
        self.image_scanner = ImageScanner()

    async def scan_url(self, url: str, scan_id: str, user_id: str):
        await manager.send_message(user_id, {
            "scan_id": scan_id,
            "status": "scanning",
            "progress": 10,
            "message": "Starting URL scan with multiple vendors..."
        })
        
        await db.scan.update(
            where={"id": scan_id},
            data={"status": "scanning"}
        )
        
        result = await self.url_scanner.scan_url(url)
        
        threat_level = "clean" if result.get("overall_verdict") == "clean" else "high"
        
        await db.scan.update(
            where={"id": scan_id},
            data={
                "status": "completed",
                "result": json.dumps(result),
                "threatLevel": threat_level,
                "endTime": datetime.utcnow()
            }
        )
        
        await manager.send_message(user_id, {
            "scan_id": scan_id,
            "status": "completed",
            "progress": 100,
            "result": result,
            "threat_level": threat_level
        })

    async def scan_pdf(self, file_content: bytes, filename: str, scan_id: str, user_id: str):
        await manager.send_message(user_id, {
            "scan_id": scan_id,
            "status": "scanning",
            "progress": 10,
            "message": "Uploading PDF to VirusTotal..."
        })
        
        await db.scan.update(
            where={"id": scan_id},
            data={"status": "scanning"}
        )
        
        result = await self.virustotal.scan_file(file_content, filename)
        
        threat_level = self._calculate_threat_level(result.get("positives", 0))
        
        await db.scan.update(
            where={"id": scan_id},
            data={
                "status": "completed",
                "result": json.dumps(result),
                "threatLevel": threat_level,
                "endTime": datetime.utcnow()
            }
        )
        
        await manager.send_message(user_id, {
            "scan_id": scan_id,
            "status": "completed",
            "progress": 100,
            "result": result,
            "threat_level": threat_level
        })

    async def scan_file(self, file_content: bytes, filename: str, scan_id: str, user_id: str):
        await manager.send_message(user_id, {
            "scan_id": scan_id,
            "status": "scanning",
            "progress": 10,
            "message": "Scanning file with ClamAV..."
        })
        
        await db.scan.update(
            where={"id": scan_id},
            data={"status": "scanning"}
        )
        
        result = await self.clamav.scan_file(file_content, filename)
        
        threat_level = "clean" if result.get("is_clean") else "high"
        
        await db.scan.update(
            where={"id": scan_id},
            data={
                "status": "completed",
                "result": json.dumps(result),
                "threatLevel": threat_level,
                "endTime": datetime.utcnow()
            }
        )
        
        await manager.send_message(user_id, {
            "scan_id": scan_id,
            "status": "completed",
            "progress": 100,
            "result": result,
            "threat_level": threat_level
        })

    async def scan_image(self, file_content: bytes, filename: str, scan_id: str, user_id: str):
        await manager.send_message(user_id, {
            "scan_id": scan_id,
            "status": "scanning",
            "progress": 10,
            "message": "Analyzing image..."
        })
        
        await db.scan.update(
            where={"id": scan_id},
            data={"status": "scanning"}
        )
        
        result = await self.image_scanner.scan(file_content, filename)
        
        threat_level = "clean" if result.get("is_clean") else "medium"
        
        await db.scan.update(
            where={"id": scan_id},
            data={
                "status": "completed",
                "result": json.dumps(result),
                "threatLevel": threat_level,
                "endTime": datetime.utcnow()
            }
        )
        
        await manager.send_message(user_id, {
            "scan_id": scan_id,
            "status": "completed",
            "progress": 100,
            "result": result,
            "threat_level": threat_level
        })

    def _calculate_threat_level(self, positives: int) -> str:
        if positives == 0:
            return "clean"
        elif positives <= 3:
            return "low"
        elif positives <= 10:
            return "medium"
        else:
            return "high"
