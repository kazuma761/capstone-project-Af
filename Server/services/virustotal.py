import aiohttp
import hashlib
from config import get_settings

settings = get_settings()

class VirusTotal:
    def __init__(self):
        self.api_key = settings.virustotal_api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    async def scan_file(self, file_content: bytes, filename: str) -> dict:
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        headers = {"x-apikey": self.api_key}
        
        try:
            # First check if file already scanned
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/files/{file_hash}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data["data"]["attributes"]["last_analysis_stats"]
                        positives = stats.get("malicious", 0)
                        total = sum(stats.values())
                        
                        # Calculate risk score based on detection rate
                        if total > 0:
                            detection_rate = (positives / total) * 100
                        else:
                            detection_rate = 0
                        
                        if positives == 0:
                            risk_score = 0
                        elif positives <= 3:
                            risk_score = 25
                        elif positives <= 10:
                            risk_score = 50
                        else:
                            risk_score = 85
                        
                        return {
                            "filename": filename,
                            "hash": file_hash,
                            "positives": positives,
                            "total": total,
                            "detection_rate": round(detection_rate, 1),
                            "stats": stats,
                            "scanner": "VirusTotal",
                            "cached": True,
                            "risk_score": risk_score,
                            "risk_features": {
                                "malware_detection": {
                                    "score": min(positives * 3, 30),
                                    "max": 30,
                                    "status": "Safe" if positives == 0 else "High Risk" if positives > 5 else "Medium Risk",
                                    "detail": f"{positives}/{total} engines detected threats ({round(detection_rate, 1)}%)"
                                },
                                "engine_coverage": {
                                    "score": 0 if total >= 60 else 10,
                                    "max": 25,
                                    "status": "Safe" if total >= 60 else "Medium Risk",
                                    "detail": f"Scanned by {total} antivirus engines"
                                },
                                "reputation": {
                                    "score": 0 if positives == 0 else 25,
                                    "max": 25,
                                    "status": "Safe" if positives == 0 else "High Risk",
                                    "detail": "Clean reputation" if positives == 0 else "Flagged by security vendors"
                                },
                                "file_analysis": {
                                    "score": 0,
                                    "max": 20,
                                    "status": "Safe",
                                    "detail": f"SHA256: {file_hash[:16]}..."
                                }
                            }
                        }
                
                # If not found, upload for scanning
                form = aiohttp.FormData()
                form.add_field('file', file_content, filename=filename)
                
                async with session.post(
                    f"{self.base_url}/files",
                    headers=headers,
                    data=form
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "filename": filename,
                            "hash": file_hash,
                            "message": "File uploaded for analysis. Results will be available in 1-2 minutes.",
                            "analysis_id": data["data"]["id"],
                            "scanner": "VirusTotal",
                            "cached": False,
                            "risk_score": 25,
                            "risk_features": {
                                "malware_detection": {
                                    "score": 10,
                                    "max": 30,
                                    "status": "Pending",
                                    "detail": "Analysis in progress..."
                                },
                                "engine_coverage": {
                                    "score": 0,
                                    "max": 25,
                                    "status": "Pending",
                                    "detail": "Waiting for scan results"
                                },
                                "reputation": {
                                    "score": 10,
                                    "max": 25,
                                    "status": "Unknown",
                                    "detail": "First time submission"
                                },
                                "file_analysis": {
                                    "score": 5,
                                    "max": 20,
                                    "status": "Pending",
                                    "detail": f"SHA256: {file_hash[:16]}..."
                                }
                            }
                        }
                    else:
                        return {
                            "error": "Failed to upload file",
                            "scanner": "VirusTotal"
                        }
        except Exception as e:
            return {
                "error": str(e),
                "scanner": "VirusTotal"
            }
