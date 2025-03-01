"""
Backward-compatibility module for audit logging utilities.
Re-exports AuditLogger from utils.logging.audit_logger.
"""
import warnings
import logging

# Set up module logger
logger = logging.getLogger(__name__)

try:
    # Re-export from the actual implementation
    from utils.logging.audit_logger import AuditLogger

    # Issue deprecation warning
    warnings.warn(
        "Importing directly from 'utils.audit_logger' is deprecated. "
        "Use 'utils.logging.audit_logger' instead.",
        DeprecationWarning,
        stacklevel=2
    )
    
    logger.debug("Successfully imported AuditLogger from utils.logging.audit_logger")

except ImportError as e:
    logger.error(f"Failed to import AuditLogger from utils.logging.audit_logger: {e}")
    
    # Fallback to re-export from utils.logging
    try:
        from utils.logging import AuditLogger
        logger.debug("Successfully imported AuditLogger from utils.logging")
    except ImportError as e:
        logger.error(f"Failed to import AuditLogger from utils.logging: {e}")
        
        # Last resort - define a stub class that logs errors
        class AuditLogger:
            """
            Stub AuditLogger class for backward compatibility.
            Logs errors when methods are called and the real implementation isn't available.
            """
            @classmethod
            def log_event(cls, *args, **kwargs):
                logger.error("AuditLogger.log_event called but the real implementation is not available")
                
            @classmethod
            def log_auth_event(cls, *args, **kwargs):
                logger.error("AuditLogger.log_auth_event called but the real implementation is not available")
                
            @classmethod
            def get_user_activity(cls, *args, **kwargs):
                logger.error("AuditLogger.get_user_activity called but the real implementation is not available")
                return []
                
            @classmethod
            def cleanup_old_logs(cls, *args, **kwargs):
                logger.error("AuditLogger.cleanup_old_logs called but the real implementation is not available")

# For compatibility with utils.logging.__init__.py exports
from utils.logging import (
    CustomJSONFormatter,
    setup_logging,
    log_event,
    log_api_request,
    log_security_event,
    cleanup_logs,
    get_log_stats
)

# Define exports
__all__ = [
    'AuditLogger',
    'CustomJSONFormatter',
    'setup_logging',
    'log_event',
    'log_api_request',
    'log_security_event',
    'cleanup_logs',
    'get_log_stats'
]
