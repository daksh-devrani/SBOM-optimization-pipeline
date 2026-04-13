import logging
import json
from datetime import datetime
from typing import Any

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "extra": record.__dict__.get("extra", {})
        }
        return json.dumps(log_entry)

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.WARNING)
    
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    
    return logger