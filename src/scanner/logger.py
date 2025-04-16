# src/scanner/logger.py
import os
import logging
from pathlib import Path
from datetime import datetime
import colorlog

def setup_logger(output_dir: Path, log_level: str) -> logging.Logger:
    """
    Set up and configure the logger.
    
    Args:
        output_dir: Directory to save log files
        log_level: Logging level (e.g., "INFO", "DEBUG")
        
    Returns:
        logging.Logger: Configured logger
    """
    logger = logging.getLogger("ai_sast")
    logger.setLevel(getattr(logging, log_level.upper()))
    logger.handlers = []  # Clear existing handlers
    
    console_handler = colorlog.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_formatter = colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    try:
        output_dir.mkdir(exist_ok=True, parents=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = output_dir / f"ai_sast_{timestamp}.log"
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        logger.info(f"Log file created: {log_file}")
    except Exception as e:
        logger.warning(f"Could not create log file: {str(e)}")
    
    return logger
