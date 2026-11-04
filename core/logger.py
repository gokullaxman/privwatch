"""
PrivWatch 3.0 - Structured & Colored Logging System
Provides both human-readable terminal output and structured JSON-lines logging for SIEM integration.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
from typing import Optional, Dict, Any




class Logger:
    """Enterprise-grade structured logger for PrivWatch platform"""

    # Color codes
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    _json_log_file: Optional[str] = None
    _log_level: str = "INFO"

    @classmethod
    def configure(cls, log_level: str = "INFO", json_log_file: Optional[str] = None):
        """Configure global logging level and optional structured JSON log file"""
        cls._log_level = log_level.upper()
        if json_log_file:
            cls._json_log_file = json_log_file
            Path(json_log_file).parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def _write_json(cls, level: str, message: str, context: Optional[Dict[str, Any]] = None):
        """Append structured JSON record to log file if enabled"""
        if not cls._json_log_file:
            return
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': level,
            'message': message,
            'context': context or {}
        }
        try:
            with open(cls._json_log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    @classmethod
    def _timestamp(cls) -> str:
        """Formatted timestamp for terminal output"""
        return datetime.now().strftime('%H:%M:%S')

    @classmethod
    def debug(cls, message: str, context: Optional[Dict[str, Any]] = None):
        if cls._log_level != "DEBUG":
            return
        prefix = f"{cls.MAGENTA}[DEBUG]{cls.RESET}"
        print(f"{prefix} [{cls._timestamp()}] {message}")
        cls._write_json("DEBUG", message, context)

    @classmethod
    def info(cls, message: str, context: Optional[Dict[str, Any]] = None):
        prefix = f"{cls.BLUE}[*]{cls.RESET}"
        print(f"{prefix} [{cls._timestamp()}] {message}")
        cls._write_json("INFO", message, context)

    @classmethod
    def success(cls, message: str, context: Optional[Dict[str, Any]] = None):
        prefix = f"{cls.GREEN}[✓]{cls.RESET}"
        print(f"{prefix} [{cls._timestamp()}] {message}")
        cls._write_json("SUCCESS", message, context)

    @classmethod
    def warning(cls, message: str, context: Optional[Dict[str, Any]] = None):
        prefix = f"{cls.YELLOW}[!]{cls.RESET}"
        print(f"{prefix} [{cls._timestamp()}] {message}")
        cls._write_json("WARNING", message, context)

    @classmethod
    def error(cls, message: str, context: Optional[Dict[str, Any]] = None):
        prefix = f"{cls.RED}[✗]{cls.RESET}"
        print(f"{prefix} [{cls._timestamp()}] {message}", file=sys.stderr)
        cls._write_json("ERROR", message, context)

    @classmethod
    def critical(cls, message: str, context: Optional[Dict[str, Any]] = None):
        prefix = f"{cls.RED}{cls.BOLD}[!!]{cls.RESET}"
        print(f"{prefix} [{cls._timestamp()}] {message}", file=sys.stderr)
        cls._write_json("CRITICAL", message, context)

    @classmethod
    def header(cls, message: str):
        print(f"\n{cls.CYAN}{cls.BOLD}{'='*60}")
        print(f"{message}")
        print(f"{'='*60}{cls.RESET}\n")

    @classmethod
    def banner(cls, mode: str, version: str = "3.0.0"):
        banner_text = f"""
{cls.CYAN}╔═══════════════════════════════════════════════════════════╗
║                  PrivWatch v{version:^5s}                     ║
║        Privilege Escalation Detection & Forensics         ║
║                  Mode: {mode.upper():^30s}    ║
╚═══════════════════════════════════════════════════════════╝{cls.RESET}
"""
        print(banner_text)
