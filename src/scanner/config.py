from dataclasses import dataclass
from typing import Optional
import os
from pathlib import Path
import re
import logging

logger = logging.getLogger("ai_sast")

@dataclass
class Config:
    openai_api_key: str
    src_dir: str
    output_dir: str
    project_name: Optional[str] = None
    model: str = "gpt-4o"  # Always use gpt-4o
    max_tokens: int = 8192
    temperature: float = 0.2
    log_level: str = "INFO"
    batch_size: int = 10
    max_retries: int = 3
    retry_delay: int = 5
    enable_codeql: bool = True
    codeql_language: str = "javascript"

    def get_logs_folder_name(self) -> str:
        """Generate a standardized logs folder name based on the source directory path"""
        if self.project_name:
            # Replace problematic characters with underscore
            sanitized_name = re.sub(r'[^\w\-]', '_', self.project_name)
            return f"{sanitized_name}_logs"
        else:
            # Use only the name of the source directory, not the full path
            path = Path(self.src_dir).resolve()
            dir_name = path.name
            # Sanitize the directory name
            sanitized_name = re.sub(r'[^\w\-]', '_', dir_name)
            return f"{sanitized_name}_logs"

def setup_config() -> Config:
    """
    Set up and validate the configuration.
    
    Returns:
        Config: Configuration object
    """
    openai_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY")
    if not openai_key:
        raise ValueError("OPENAI_API_KEY or OPENAI_KEY environment variable is required")
    
    # Default to the /project directory structure
    base_dir = Path("/project")
    
    # Default source and output directories
    src_dir = os.getenv("SRC_DIR", str(base_dir / "input"))
    if not os.path.isdir(src_dir):
        logger.warning(f"Source directory {src_dir} doesn't exist or is not a directory")
    
    output_dir = os.getenv("OUTPUT_DIR", str(base_dir / "output"))
    if not os.path.isdir(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
            logger.info(f"Created output directory: {output_dir}")
        except Exception as e:
            raise ValueError(f"Could not create output directory {output_dir}: {str(e)}")
    
    if not os.access(output_dir, os.W_OK):
        raise ValueError(f"Output directory {output_dir} is not writable")
    
    project_name = os.getenv("PROJECT_NAME")
    
    # Always use GPT-4o model
    model = "gpt-4o"
    max_tokens = int(os.getenv("MAX_TOKENS", "8192"))
    temperature = float(os.getenv("TEMPERATURE", "0.2"))
    log_level = os.getenv("LOG_LEVEL", "INFO")
    batch_size = int(os.getenv("BATCH_SIZE", "10"))
    max_retries = int(os.getenv("MAX_RETRIES", "3"))
    retry_delay = int(os.getenv("RETRY_DELAY", "5"))
    enable_codeql = os.getenv("ENABLE_CODEQL", "true").lower() in ("true", "1", "yes")
    codeql_language = os.getenv("CODEQL_LANGUAGE", "javascript")

    logger.info(f"Configuration: src_dir={src_dir}, output_dir={output_dir}, model={model}")
    
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
        retry_delay=retry_delay,
        enable_codeql=enable_codeql,
        codeql_language=codeql_language
    )
