import os
import asyncio
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from services.scanner_router import ScannerRouter
from services.websocket_manager import manager
from database import db
import mimetypes

class DownloadFolderHandler(FileSystemEventHandler):
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.scanner = ScannerRouter()
        self.processing = set()  # Track files being processed
        
    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        
        # Ignore temp files
        if file_path.endswith(('.tmp', '.crdownload', '.part')):
            return
        
        # Avoid duplicate processing
        if file_path in self.processing:
            return
        
        self.processing.add(file_path)
        
        # Schedule async scan
        asyncio.create_task(self.scan_new_file(file_path))
    
    def on_deleted(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        
        # Notify dashboard about file deletion
        asyncio.create_task(manager.send_message(self.user_id, {
            "type": "file_deleted",
            "file_path": file_path,
            "filename": os.path.basename(file_path)
        }))
    
    def on_modified(self, event):
        # Ignore modifications for now to avoid duplicate scans
        pass
    
    async def scan_new_file(self, file_path: str):
        try:
            # Wait a bit for file to finish downloading
            await asyncio.sleep(2)
            
            if not os.path.exists(file_path):
                self.processing.discard(file_path)
                return
            
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Skip very large files (>100MB)
            if file_size > 100 * 1024 * 1024:
                await manager.send_message(self.user_id, {
                    "type": "file_skipped",
                    "filename": filename,
                    "reason": "File too large (>100MB)"
                })
                self.processing.discard(file_path)
                return
            
            # Notify dashboard about new file
            await manager.send_message(self.user_id, {
                "type": "file_detected",
                "filename": filename,
                "file_path": file_path,
                "size": file_size
            })
            
            # Determine scan type based on file extension
            scan_type = self.get_scan_type(filename)
            
            # Create scan record
            scan_record = await db.scan.create(
                data={
                    "userId": self.user_id,
                    "scanType": scan_type,
                    "target": filename,
                    "status": "pending"
                }
            )
            
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Notify dashboard scan started
            await manager.send_message(self.user_id, {
                "type": "auto_scan_started",
                "scan_id": scan_record.id,
                "filename": filename,
                "scan_type": scan_type
            })
            
            # Perform scan based on type
            if scan_type == "pdf":
                await self.scanner.scan_pdf(file_content, filename, scan_record.id, self.user_id)
            elif scan_type == "image":
                await self.scanner.scan_image(file_content, filename, scan_record.id, self.user_id)
            else:
                await self.scanner.scan_file(file_content, filename, scan_record.id, self.user_id)
            
            self.processing.discard(file_path)
            
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            self.processing.discard(file_path)
            await manager.send_message(self.user_id, {
                "type": "scan_error",
                "filename": os.path.basename(file_path),
                "error": str(e)
            })
    
    def get_scan_type(self, filename: str) -> str:
        """Determine scan type based on file extension"""
        ext = os.path.splitext(filename)[1].lower()
        
        if ext == '.pdf':
            return 'pdf'
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
            return 'image'
        else:
            return 'file'


class FolderMonitorService:
    def __init__(self):
        self.observers = {}  # user_id -> Observer
        
    def start_monitoring(self, user_id: str, folder_path: str = None):
        """Start monitoring download folder for a user"""
        if user_id in self.observers:
            return  # Already monitoring
        
        # Use default Downloads folder if not specified
        if not folder_path:
            folder_path = str(Path.home() / "Downloads")
        
        if not os.path.exists(folder_path):
            print(f"Download folder not found: {folder_path}")
            return
        
        event_handler = DownloadFolderHandler(user_id)
        observer = Observer()
        observer.schedule(event_handler, folder_path, recursive=False)
        observer.start()
        
        self.observers[user_id] = observer
        print(f"✅ Started monitoring {folder_path} for user {user_id}")
    
    def stop_monitoring(self, user_id: str):
        """Stop monitoring for a user"""
        if user_id in self.observers:
            self.observers[user_id].stop()
            self.observers[user_id].join()
            del self.observers[user_id]
            print(f"⏹️ Stopped monitoring for user {user_id}")
    
    def stop_all(self):
        """Stop all monitoring"""
        for user_id in list(self.observers.keys()):
            self.stop_monitoring(user_id)


# Global instance
folder_monitor = FolderMonitorService()
