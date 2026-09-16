from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
from config import get_settings
from database import get_db

router = APIRouter()
settings = get_settings()
security = HTTPBearer()

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Extract and validate current user from JWT token"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        user_id = payload.get("sub")
        email = payload.get("email")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"id": user_id, "email": email}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    name: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm="HS256")

@router.post("/signup", response_model=TokenResponse)
async def signup(request: SignupRequest, db = Depends(get_db)):
    existing = await db.user.find_unique(where={"email": request.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(request.password)
    user = await db.user.create(
        data={
            "email": request.email,
            "password": hashed_password,
            "name": request.name
        }
    )
    
    token = create_access_token({"sub": user.id, "email": user.email})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user.id, "email": user.email, "name": user.name}
    }

@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db = Depends(get_db)):
    user = await db.user.find_unique(where={"email": request.email})
    if not user or not verify_password(request.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Start folder monitoring for this user
    from services.folder_monitor import folder_monitor
    folder_monitor.start_monitoring(user.id)
    
    token = create_access_token({"sub": user.id, "email": user.email})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user.id, "email": user.email, "name": user.name}
    }
