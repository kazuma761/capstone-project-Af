from fastapi import WebSocket
from typing import Dict
from enum import Enum


class MessageType(str, Enum):
    """WebSocket message types"""
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETE = "scan_complete"
    THREAT_DETECTED = "threat_detected"
    BEHAVIORAL_UPDATE = "behavioral_update"
    BEHAVIORAL_ALERT = "behavioral_alert"
    PROCESS_KILLED = "process_killed"


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]

    async def send_message(self, client_id: str, message: dict):
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_json(message)
            except:
                self.disconnect(client_id)
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        disconnected = []
        for client_id, websocket in self.active_connections.items():
            try:
                await websocket.send_json(message)
            except:
                disconnected.append(client_id)
        
        for client_id in disconnected:
            self.disconnect(client_id)
    
    async def send_behavioral_update(self, data: dict):
        """Send behavioral monitor update to all clients"""
        message = {
            "type": MessageType.BEHAVIORAL_UPDATE.value,
            "data": data
        }
        await self.broadcast(message)
    
    async def send_behavioral_alert(self, alert: dict):
        """Send behavioral alert to all clients"""
        message = {
            "type": MessageType.BEHAVIORAL_ALERT.value,
            "data": alert
        }
        await self.broadcast(message)
    
    async def send_process_killed(self, process_info: dict):
        """Send process killed notification"""
        message = {
            "type": MessageType.PROCESS_KILLED.value,
            "data": process_info
        }
        await self.broadcast(message)


manager = ConnectionManager()
