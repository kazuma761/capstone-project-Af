from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from api.scan import get_current_user
from services.chatbot import chatbot

router = APIRouter()

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    conversation_history: Optional[List[Message]] = None

class ChatResponse(BaseModel):
    response: str

@router.post("/chat", response_model=ChatResponse)
async def chat_with_bot(
    request: ChatRequest,
    user_id: str = Depends(get_current_user)
):
    """
    Chat with the AI security assistant
    """
    try:
        # Convert conversation history to dict format
        history = None
        if request.conversation_history:
            history = [
                {"role": msg.role, "content": msg.content}
                for msg in request.conversation_history
            ]
        
        # Get response from chatbot
        response = await chatbot.chat(request.message, history)
        
        return ChatResponse(response=response)
    
    except Exception as e:
        print(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
