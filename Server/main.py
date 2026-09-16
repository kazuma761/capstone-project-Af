from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from services.websocket_manager import manager
from services.folder_monitor import folder_monitor
from database import db
from config import get_settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.connect()
    yield
    # Cleanup
    folder_monitor.stop_all()
    await db.disconnect()

app = FastAPI(title="Cyber Detection API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in get_settings().cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from api import auth, scan, monitor, downloads, chatbot, behavioral

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(scan.router, prefix="/api/scan", tags=["scan"])
app.include_router(monitor.router, prefix="/api/monitor", tags=["monitor"])
app.include_router(downloads.router, prefix="/api/downloads", tags=["downloads"])
app.include_router(chatbot.router, prefix="/api/chatbot", tags=["chatbot"])
app.include_router(behavioral.router, prefix="/api/behavioral", tags=["behavioral"])

@app.get("/")
async def root():
    return {"message": "Cyber Detection API is running"}

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await manager.connect(websocket, client_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(client_id)
