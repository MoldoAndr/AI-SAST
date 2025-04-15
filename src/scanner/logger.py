"""
Logger module for AI_SAST.

Sets up logging with appropriate formatting and output options.
"""

import os
import logging
import sys
from pathlib import Path
from datetime import datetime
import colorlog

from .config import Config


def setup_logger(config: Config) -> logging.Logger:
    """
    Set up and configure the logger.
    
    Args:
        config: Configuration object
        
    Returns:
        logging.Logger: Configured logger
    """
    # Create logger
    logger = logging.getLogger("ai_sast")
    logger.setLevel(getattr(logging, config.log_level.upper()))
    logger.handlers = []  # Clear existing handlers
    
    # Create console handler with color formatting
    console_handler = colorlog.StreamHandler()
    console_handler.setLevel(getattr(logging, config.log_level.upper()))
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
    
    # Create file handler for detailed logging
    try:
        log_dir = Path(config.output_dir) / "logs"
        log_dir.mkdir(exist_ok=True, parents=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"ai_sast_{timestamp}.log"
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file
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