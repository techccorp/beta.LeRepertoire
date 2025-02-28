"""
Application defense utilities for security, rate limiting, and validation.

This package provides:
- Security utilities for secure token generation and input sanitization
- Rate limiting implementation for API protection
- Comprehensive validation functions for data integrity
"""

from .security_utils import (
    generate_random_string,
    generate_secure_token,
    generate_id_with_prefix,
    hash_string,
    constant_time_compare,
    generate_session_id,
    sanitize_input,
    log_security_event
)

from .rate_limiter import RateLimiter

from .validation_utils import (
    validate_request_data,
    validate_id_format,
    validate_uuid,
    validate_email,
    validate_date_format,
    validate_phone_number,
    validate_required_fields,
    validate_field_length,
    validate_numeric_range,
    log_validation_error,
    sanitize_filename,
    validate_business_data,
    validate_venue_data,
    validate_work_area_data
)

__all__ = [
    # Security Utilities
    'generate_random_string',
    'generate_secure_token',
    'generate_id_with_prefix',
    'hash_string',
    'constant_time_compare',
    'generate_session_id',
    'sanitize_input',
    'log_security_event',
    
    # Rate Limiting
    'RateLimiter',
    
    # Validation Utilities
    'validate_request_data',
    'validate_id_format',
    'validate_uuid',
    'validate_email',
    'validate_date_format',
    'validate_phone_number',
    'validate_required_fields',
    'validate_field_length',
    'validate_numeric_range',
    'log_validation_error',
    'sanitize_filename',
    'validate_business_data',
    'validate_venue_data',
    'validate_work_area_data'
]

# Initialize package logger
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())
