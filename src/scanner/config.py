from dataclasses import dataclass
from typing import Optional
import os
from pathlib import Path
import re

@dataclass
class Config:
    openai_api_key: str
    src_dir: str
    output_dir: str
    project_name: Optional[str] = None
    model: str = "gpt-4-turbo"
    max_tokens: int = 8192
    temperature: float = 0.2
    log_level: str = "INFO"
    batch_size: int = 10
    max_retries: int = 3
    retry_delay: int = 5
    
    def get_logs_folder_name(self) -> str:
        """Generate a standardized logs folder name based on the source directory path"""
        if self.project_name:
            # Înlocuiește caracterele problematice cu underscore
            sanitized_name = re.sub(r'[^\w\-]', '_', self.project_name)
            return f"{sanitized_name}_logs"
        else:
            # Utilizăm doar numele directorului sursă, nu path-ul complet
            path = Path(self.src_dir).resolve()
            dir_name = path.name
            # Sanitizăm numele directorului
            sanitized_name = re.sub(r'[^\w\-]', '_', dir_name)
            return f"{sanitized_name}_logs"

def setup_config() -> Config:
    openai_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY")
    if not openai_key:
        raise ValueError("OPENAI_API_KEY or OPENAI_KEY environment variable is required")
    
    src_dir = os.getenv("SRC_DIR", "/app/src")
    if not os.path.isdir(src_dir):
        raise ValueError(f"Source directory {src_dir} does not exist or is not a directory")
    
    output_dir = os.getenv("OUTPUT_DIR", "/logs")
    if not os.path.isdir(output_dir):
        raise ValueError(f"Output directory {output_dir} does not exist or is not a directory")
    
    if not os.access(output_dir, os.W_OK):
        raise ValueError(f"Output directory {output_dir} is not writable")
    
    project_name = os.getenv("PROJECT_NAME")
    
    model = os.getenv("OPENAI_MODEL", "gpt-4-turbo")
    max_tokens = int(os.getenv("MAX_TOKENS", "8192"))
    temperature = float(os.getenv("TEMPERATURE", "0.2"))
    log_level = os.getenv("LOG_LEVEL", "INFO")
    batch_size = int(os.getenv("BATCH_SIZE", "10"))
    max_retries = int(os.getenv("MAX_RETRIES", "3"))
    retry_delay = int(os.getenv("RETRY_DELAY", "5"))
    
    return Config(
        openai_api_key=openai_key,
        src_dir=src_dir,
        output_dir=output_dir,
        project_name=project_name,
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        log_level=log_level,
        batch_size=batch_size,
        max_retries=max_retries,
        retry_delay=retry_delay
    )