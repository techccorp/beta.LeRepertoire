# --------------------------------------------#
#      utils/defense/security_utils.py        #
# --------------------------------------------#
import string
import secrets
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def generate_random_string(length=30):
    """Generate a random string for OAuth state."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

def generate_secure_token(length=64):
    """Generate a secure token for authentication purposes."""
    return secrets.token_urlsafe(length)

def generate_id_with_prefix(prefix, length=8):
    """Generate an ID with a specific prefix (e.g., USR-, BUS-, etc.)"""
    random_part = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))
    return f"{prefix}-{random_part}"

def hash_string(value):
    """Create a secure hash of a string."""
    return secrets.token_hex(32)

def constant_time_compare(val1, val2):
    """
    Compare two strings in constant time to prevent timing attacks.
    """
    return secrets.compare_digest(str(val1), str(val2))

def generate_session_id():
    """Generate a secure session ID."""
    return secrets.token_urlsafe(32)

def sanitize_input(input_string):
    """Basic input sanitization."""
    if not isinstance(input_string, str):
        return ""
    # Remove any control characters
    return ''.join(char for char in input_string if char in string.printable)

def log_security_event(event_type, details, severity="INFO"):
    """Log security-related events."""
    try:
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "severity": severity,
            "details": details
        }
        logger.info(f"Security Event: {event}")
    except Exception as e:
        logger.error(f"Failed to log security event: {str(e)}")
