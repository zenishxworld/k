"""
logger.py - Centralized logging configuration for the vulnerability scanner.

Configures both file and console handlers so every scan event
(start, end, errors, discoveries) is recorded in the logs/ directory.
"""

import logging
import os
from datetime import datetime


def setup_logger(name: str = "vuln_scanner") -> logging.Logger:
    """
    Create and return a configured logger instance.

    - Logs are saved to  logs/scan_<timestamp>.log
    - Console output uses INFO level
    - File output uses DEBUG level (captures everything)

    Args:
        name: Logger name identifier.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    # Prevent duplicate handlers if setup_logger is called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # ---------- logs/ directory ----------
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"scan_{timestamp}.log")

    # ---------- File handler (DEBUG and above) ----------
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)

    # ---------- Console handler (INFO and above) ----------
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )
    console_handler.setFormatter(console_fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.debug("Logger initialised – log file: %s", log_file)
    return logger
