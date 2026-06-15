import logging
import json
from datetime import datetime
from functools import wraps
import sys

class JsonFormatter(logging.Formatter):
    """
    Format logs as JSON objects for SIEM (Splunk, Elastic) compatibility.
    """
    def format(self, record):
        log_obj = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "funcName": record.funcName,
            "lineNo": record.lineno
        }
        
        # Add extra fields if passed via 'extra=' dictionary
        if hasattr(record, 'extra_fields'):
            log_obj.update(record.extra_fields)
            
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_obj)

def get_logger(name: str):
    """
    Returns a configured JSON logger for the AI SOC platform.
    """
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        
    return logger

def log_execution_time(logger):
    """Decorator to log function execution time"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = datetime.utcnow()
            result = await func(*args, **kwargs)
            duration = (datetime.utcnow() - start).total_seconds()
            logger.info(f"Executed {func.__name__} in {duration:.3f}s", extra={'extra_fields': {'duration_s': duration}})
            return result
            
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = datetime.utcnow()
            result = func(*args, **kwargs)
            duration = (datetime.utcnow() - start).total_seconds()
            logger.info(f"Executed {func.__name__} in {duration:.3f}s", extra={'extra_fields': {'duration_s': duration}})
            return result
            
        import inspect
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    return decorator
