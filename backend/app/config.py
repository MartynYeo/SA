from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Database settings
    database_url: str = "postgresql://user:password@localhost/iamviewer"

    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000

    # Gemini API
    gemini_api_key: Optional[str] = None
    # Feature flags
    llm_disabled: bool = False

    class Config:
        env_file = ".env"

settings = Settings()
