import os
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file.
    
    The GEMINI_API_KEY can be set via:
    1. Environment variable: GEMINI_API_KEY
    2. .env file in the project root
    """
    # Gemini API
    GEMINI_API_KEY: Optional[str] = Field(
        default=None,
        description="Google Gemini API key for LLM extraction"
    )

    class Config:
        env_file = ".env"
        case_sensitive = True

    @field_validator('GEMINI_API_KEY', mode='after')
    @classmethod
    def validate_api_key(cls, v: Optional[str]) -> str:
        """Ensure GEMINI_API_KEY is set and not empty."""
        if not v or not v.strip():
            raise ValueError(
                "GEMINI_API_KEY is not configured. "
                "Please set it via environment variable or add it to your .env file:\n"
                "  GEMINI_API_KEY=your_api_key_here"
            )
        return v.strip()


# Load settings with validation
try:
    settings = Settings()
except Exception as e:
    raise RuntimeError(
        f"Failed to load application settings: {e}\n"
        "Make sure GEMINI_API_KEY is set in your environment or .env file."
    ) from e
