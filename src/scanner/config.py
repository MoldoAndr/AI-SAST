"""
Configuration module for AI_SAST.

Handles loading and validating configuration from environment variables.
"""

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    """Configuration class for AI_SAST."""
    openai_api_key: str
    src_dir: str
    output_dir: str
    model: str = "gpt-4-turbo"
    max_tokens: int = 8192
    temperature: float = 0.2
    log_level: str = "INFO"
    batch_size: int = 10
    max_retries: int = 3
    retry_delay: int = 5


def setup_config() -> Config:
    """
    Load and validate configuration from environment variables.
    
    Returns:
        Config: Configuration object
    
    Raises:
        ValueError: If required environment variables are missing
    """
    # Check for required environment variables
    openai_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY")
    if not openai_key:
        raise ValueError("OPENAI_API_KEY or OPENAI_KEY environment variable is required")
    
    # Source directory (default to /app/src if not specified)
    src_dir = os.getenv("SRC_DIR", "/app/src")
    if not os.path.isdir(src_dir):
        raise ValueError(f"Source directory {src_dir} does not exist or is not a directory")
    
    # Output directory (default to /logs if not specified)
    output_dir = os.getenv("OUTPUT_DIR", "/logs")
    if not os.path.isdir(output_dir):
        raise ValueError(f"Output directory {output_dir} does not exist or is not a directory")
    
    # Optional configuration
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
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        log_level=log_level,
        batch_size=batch_size,
        max_retries=max_retries,
        retry_delay=retry_delay
    )