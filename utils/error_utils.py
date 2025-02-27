# -----------------------------------------------#
#              utils/error_utils.py              #
# -----------------------------------------------#
import logging
import traceback
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, Optional
from flask import current_app, request, jsonify
from functools import wraps

logger = logging.getLogger(__name__)

class AppError(Exception):
    """Base error class for application errors"""
    def __init__(self, message: str, error_code: str, status_code: int = 500):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(self.message)

class ValidationError(AppError):
    """Validation error class"""
    def __init__(self, message: str, error_code: str = 'VALIDATION_ERROR'):
        super().__init__(message, error_code, status_code=400)

class AuthenticationError(AppError):
    """Authentication error class"""
    def __init__(self, message: str, error_code: str = 'AUTH_ERROR'):
        super().__init__(message, error_code, status_code=401)

class PermissionError(AppError):
    """Permission error class"""
    def __init__(self, message: str, error_code: str = 'PERMISSION_ERROR'):
        super().__init__(message, error_code, status_code=403)

class NotFoundError(AppError):
    """Not found error class"""
    def __init__(self, message: str, error_code: str = 'NOT_FOUND'):
        super().__init__(message, error_code, status_code=404)

class DatabaseError(AppError):
    """Database error class"""
    def __init__(self, message: str, error_code: str = 'DATABASE_ERROR'):
        super().__init__(message, error_code, status_code=500)

def handle_error(error: Exception) -> Tuple[Dict[str, Any], int]:
    """
    Handle and format error response
    """
    if isinstance(error, AppError):
        status_code = error.status_code
        error_code = error.error_code
        message = error.message
    else:
        status_code = 500
        error_code = 'INTERNAL_ERROR'
        message = 'An unexpected error occurred'

    error_response = {
        'success': False,
        'error': {
            'code': error_code,
            'message': message
        }
    }
    # ------------------------------------------------------------#
    #                   Log error with context                    #
    # ------------------------------------------------------------#
    log_error(error, error_code, status_code)

    return error_response, status_code

def log_error(
    error: Exception,
    error_code: str,
    status_code: int,
    context: Optional[Dict] = None
) -> None:
    """
    Log error with detailed context
    """
    try:
        error_context = {
            'timestamp': datetime.utcnow().isoformat(),
            'error_code': error_code,
            'status_code': status_code,
            'error_type': error.__class__.__name__,
            'error_message': str(error),
            'traceback': traceback.format_exc(),
            'request': {
                'url': request.url if request else None,
                'method': request.method if request else None,
                'headers': dict(request.headers) if request else None,
                'args': dict(request.args) if request else None
            }
        }

        if context:
            error_context['additional_context'] = context

        if status_code >= 500:
            logger.error(f"Server Error: {error_context}")
        else:
            logger.warning(f"Client Error: {error_context}")

        # ------------------------------------------------------------#
        #              Store error in database if configured          #
        # ------------------------------------------------------------#
        if current_app.config.get('ERROR_LOGGING_ENABLED', True):
            try:
                current_app.mongo.db.error_logs.insert_one(error_context)
            except Exception as db_error:
                logger.error(f"Failed to store error log: {str(db_error)}")

    except Exception as logging_error:
        logger.error(f"Error during error logging: {str(logging_error)}")

def format_error_response(
    message: str,
    error_code: str,
    status_code: int = 400,
    details: Optional[Dict] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Format error response
    """
    response = {
        'success': False,
        'error': {
            'code': error_code,
            'message': message
        }
    }

    if details:
        response['error']['details'] = details

    return response, status_code

def validate_or_raise(condition: bool, message: str, error_code: str = 'VALIDATION_ERROR') -> None:
    """
    Validate condition or raise ValidationError
    """
    if not condition:
        raise ValidationError(message, error_code)

def assert_found(item: Any, message: str, error_code: str = 'NOT_FOUND') -> None:
    """
    Assert item exists or raise NotFoundError
    """
    if not item:
        raise NotFoundError(message, error_code)

def assert_valid(condition: bool, message: str, error_code: str = 'VALIDATION_ERROR') -> None:
    """
    Assert condition is valid or raise ValidationError
    """
    if not condition:
        raise ValidationError(message, error_code)

def assert_permitted(condition: bool, message: str, error_code: str = 'PERMISSION_ERROR') -> None:
    """
    Assert operation is permitted or raise PermissionError
    """
    if not condition:
        raise PermissionError(message, error_code)

def get_error_context() -> Dict[str, Any]:
    """
    Get current error context
    """
    return {
        'timestamp': datetime.utcnow().isoformat(),
        'request': {
            'url': request.url if request else None,
            'method': request.method if request else None,
            'headers': dict(request.headers) if request else None,
            'args': dict(request.args) if request else None
        },
        'app_context': {
            'environment': current_app.config.get('ENV'),
            'debug': current_app.config.get('DEBUG')
        }
    }

def cleanup_error_logs(db, days_to_keep: int = 30) -> None:
    """
    Clean up old error logs
    """
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        result = db.error_logs.delete_many({
            'timestamp': {'$lt': cutoff_date.isoformat()}
        })
        logger.info(f"Cleaned up {result.deleted_count} old error logs")
    except Exception as e:
        logger.error(f"Error cleaning up error logs: {str(e)}")

def api_route_with_error_handling(func):
    """
    Decorator for API routes with standardized error handling.
    
    Usage:
        @app.route('/api/resource')
        @api_route_with_error_handling
        def get_resource():
            # Any AppError subclass will be properly handled
            # Return response as normal
            
    Returns a properly formatted JSON error response if any exception occurs.
    Handles all AppError subclasses with their appropriate status codes.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except AppError as e:
            error_response, status_code = handle_error(e)
            return jsonify(error_response), status_code
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {str(e)}")
            error_response, status_code = format_error_response(
                "An unexpected error occurred", 
                "INTERNAL_ERROR", 
                500
            )
            return jsonify(error_response), status_code
    return wrapper
