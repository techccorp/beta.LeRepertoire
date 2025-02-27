"""
Logging and audit utilities for application monitoring and security.

Provides structured logging, audit trail functionality, and security event tracking.
Includes MongoDB integration for log storage and retrieval.
"""

from .audit_logger import AuditLogger
from .logging_utils import (
    CustomJSONFormatter,
    setup_logging,
    log_event,
    log_api_request,
    log_security_event,
    cleanup_logs,
    get_log_stats
)

__all__ = [
    # Audit logging
    'AuditLogger',
    
    # Logging configuration
    'CustomJSONFormatter',
    'setup_logging',
    
    # Logging functions
    'log_event',
    'log_api_request',
    'log_security_event',
    
    # Log management
    'cleanup_logs',
    'get_log_stats'
]

# Initialize package logger
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())
