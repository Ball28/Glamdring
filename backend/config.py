from pydantic_settings import BaseSettings
from typing import Optional
from pathlib import Path


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Glamdring"
    VERSION: str = "1.0.0"
    
    # Server
    HOST: str = "127.0.0.1"  # Localhost only for security
    PORT: int = 8000
    
    # VirusTotal API (optional)
    VT_API_KEY: Optional[str] = None
    VT_RATE_LIMIT: int = 4  # Free tier: 4 requests/minute
    
    # File Upload
    MAX_UPLOAD_SIZE: int = 100 * 1024 * 1024  # 100MB
    ALLOWED_EXTENSIONS: set = {
        ".exe", ".dll", ".sys", ".bin", ".msi",  # Executables
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",  # Documents
        ".zip", ".rar", ".7z", ".tar", ".gz",  # Archives
        ".js", ".vbs", ".ps1", ".bat", ".cmd", ".sh",  # Scripts
        ".txt", ".log", ".py"  # Text/Code
    }
    
    # Analysis
    DEFAULT_TIMEOUT: int = 300  # 5 minutes
    
    # Paths (will be in ~/.malware-analyzer/)
    @property
    def data_dir(self) -> Path:
        path = Path.home() / ".malware-analyzer"
        path.mkdir(exist_ok=True)
        return path
    
    @property
    def samples_dir(self) -> Path:
        path = self.data_dir / "samples"
        path.mkdir(exist_ok=True)
        return path
    
    @property
    def db_path(self) -> Path:
        return self.data_dir / "local.db"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
