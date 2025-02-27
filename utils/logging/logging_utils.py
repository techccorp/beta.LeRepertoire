# -------------------------------------------#
#       utils/logging/logging_utils.py       #
# -------------------------------------------#
import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
from flask import request, g, current_app
import traceback
import os
from logging.handlers import RotatingFileHandler

# ------------------------------#
#     Configure base logger     #
# ------------------------------#
logger = logging.getLogger(__name__)

class CustomJSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        """Format log record as JSON"""
        timestamp = datetime.utcnow().isoformat()
        
        log_data = {
            'timestamp': timestamp,
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # -------------------------------------------#
        #      Add request context if available      #
        # -------------------------------------------#
        if request:
            log_data['request'] = {
                'url': request.url,
                'method': request.method,
                'path': request.path,
                'remote_addr': request.remote_addr
            }
        # -------------------------------------#
        #      Add user context if available
        # -------------------------------------#
        if hasattr(g, 'user'):
            log_data['user'] = {
                'payroll_id': g.user.get('payroll_id'),
                'role': g.user.get('role')
            }
        # -------------------------------------#
        # Add error information if present
        # -------------------------------------#
        if record.exc_info:
            log_data['error'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }

        return json.dumps(log_data)

def setup_logging(app_name: str, log_level: str = 'INFO') -> None:
    """
    Setup application logging with file and console handlers
    """
    # Create logs directory if it doesn't exist
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    # -------------------------------------#
    # Configure root logger
    # -------------------------------------#
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    # -------------------------------------#
    # Create console handler
    # -------------------------------------#
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(CustomJSONFormatter())
    root_logger.addHandler(console_handler)
    # -------------------------------------#
    # Create file handler
    # -------------------------------------#
    file_handler = RotatingFileHandler(
        filename=f'logs/{app_name}.log',
        maxBytes=10485760,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(CustomJSONFormatter())
    root_logger.addHandler(file_handler)

    logger.info(f"Logging initialized for {app_name}")

def log_event(
    event_type: str,
    message: str,
    context: Optional[Dict] = None,
    level: str = 'INFO'
) -> None:
    """
    Log an application event with context
    """
    try:
        event_data = {
            'event_type': event_type,
            'message': message,
            'timestamp': datetime.utcnow().isoformat()
        }

        if context:
            event_data['context'] = context
        
        # -------------------------------------#
        # Add request context if available
        # -------------------------------------#
        if request:
            event_data['request'] = {
                'url': request.url,
                'method': request.method,
                'remote_addr': request.remote_addr
            }
        # -------------------------------------#
        # Add user context if available
        # -------------------------------------#
        if hasattr(g, 'user'):
            event_data['user'] = {
                'payroll_id': g.user.get('payroll_id'),
                'role': g.user.get('role')
            }

        # -------------------------------------#
        # Log at appropriate level
        # -------------------------------------#
        log_func = getattr(logger, level.lower())
        log_func(json.dumps(event_data))

        # -------------------------------------#
        # Store in database if configured
        # -------------------------------------#
        if current_app.config.get('EVENT_LOGGING_ENABLED', True):
            try:
                current_app.mongo.db.event_logs.insert_one(event_data)
            except Exception as e:
                logger.error(f"Failed to store event log: {str(e)}")

    except Exception as e:
        logger.error(f"Error logging event: {str(e)}")

def log_api_request(response: Any) -> None:
    """
    Log API request details
    """
    try:
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'request': {
                'method': request.method,
                'url': request.url,
                'path': request.path,
                'args': dict(request.args),
                'headers': dict(request.headers),
                'remote_addr': request.remote_addr
            },
            'response': {
                'status_code': response.status_code,
                'content_length': response.content_length
            }
        }
        # -------------------------------------#
        # Add user context if available
        # -------------------------------------#
        if hasattr(g, 'user'):
            log_data['user'] = {
                'payroll_id': g.user.get('payroll_id'),
                'role': g.user.get('role')
            }
        # -------------------------------------#
        # Add request duration if available
        # -------------------------------------#
        if hasattr(g, 'start_time'):
            duration = datetime.utcnow() - g.start_time
            log_data['duration_ms'] = duration.total_seconds() * 1000

        logger.info(json.dumps(log_data))

    except Exception as e:
        logger.error(f"Error logging API request: {str(e)}")

def log_security_event(
    event_type: str,
    user_id: str,
    action: str,
    success: bool,
    details: Optional[Dict] = None
) -> None:
    """
    Log security-related events
    """
    try:
        security_event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'action': action,
            'success': success,
            'ip_address': request.remote_addr if request else None
        }

        if details:
            security_event['details'] = details

        logger.info(json.dumps(security_event))

        # Store in database if configured
        if current_app.config.get('SECURITY_LOGGING_ENABLED', True):
            try:
                current_app.mongo.db.security_logs.insert_one(security_event)
            except Exception as e:
                logger.error(f"Failed to store security log: {str(e)}")

    except Exception as e:
        logger.error(f"Error logging security event: {str(e)}")

def cleanup_logs(db, days_to_keep: int = 30) -> None:
    """
    Clean up old logs from the database
    """
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        # Clean up event logs
        event_result = db.event_logs.delete_many({
            'timestamp': {'$lt': cutoff_date.isoformat()}
        })
        logger.info(f"Cleaned up {event_result.deleted_count} old event logs")

        # Clean up security logs
        security_result = db.security_logs.delete_many({
            'timestamp': {'$lt': cutoff_date.isoformat()}
        })
        logger.info(f"Cleaned up {security_result.deleted_count} old security logs")

    except Exception as e:
        logger.error(f"Error cleaning up logs: {str(e)}")

def get_log_stats(db) -> Dict[str, Any]:
    """
    Get logging statistics
    """
    try:
        return {
            'event_logs': db.event_logs.count_documents({}),
            'security_logs': db.security_logs.count_documents({}),
            'error_logs': db.error_logs.count_documents({})
        }
    except Exception as e:
        logger.error(f"Error getting log stats: {str(e)}")
        return {}
