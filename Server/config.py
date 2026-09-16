from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    google_safe_browsing_api_key: str
    virustotal_api_key: str
    groq_api_key: str
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()
