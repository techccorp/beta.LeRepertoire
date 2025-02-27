"""
Authentication utilities for the payroll application.
Provides session management, permission handling, and authentication services.
"""

from .session_utils import SessionManager, SessionExpiredError
from .auth_manager import AuthManager

# Import functions to be exposed at the module level
from .auth_utils import (
    validate_payroll_id,
    hash_password,
    check_password,
    generate_token,
    verify_token
)

# Export for external use
__all__ = [
    'SessionManager',
    'SessionExpiredError',
    'AuthManager',
    'validate_payroll_id',
    'hash_password',
    'check_password',
    'generate_token',
    'verify_token'
]
