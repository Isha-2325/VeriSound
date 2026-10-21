import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = DATA_DIR / "evidence"
REPORTS_DIR = DATA_DIR / "reports"
DATABASE_PATH = DATA_DIR / "forensic_suite.db"

# Ensure runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseModel):
    PROJECT_NAME: str = "AudioForensicSuite"
    VERSION: str = "1.0.0"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "af98e1b3d752c04ef3a72b8c9d10e4a77b819f02ec3d5b7a1e0c9f8a7b6d5c4e")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours session
    
    # Forensic Settings
    MAX_FILE_SIZE_MB: int = 150
    ALLOWED_EXTENSIONS: set = {".wav", ".mp3", ".flac", ".ogg", ".aac", ".m4a"}
    ENF_NOMINAL_FREQUENCIES: list = [50.0, 60.0]
    
    # Database
    DB_URL: str = f"sqlite:///{DATABASE_PATH}"

settings = Settings()
