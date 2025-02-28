# config/__init__.py
"""
Central configuration exports for the application.
Combines base configuration with payroll constants.
"""

# 1. Import Core Configuration
from .base_config import Config

# 2. Import Payroll Constants
from .payroll_config import (
    DEFAULT_PAYMENT_REFERENCE_PREFIX,
    SUPERANNUATION_RATE,
    STANDARD_HOURS,
    LEAVE_ENTITLEMENTS,
    LEAVE_MAPPING,
    TAX_BRACKETS,
    PERIOD_DIVISORS
)

# 3. Explicit Exports
__all__ = [
    # Core Configuration
    'Config',
    
    # Payroll Constants
    'DEFAULT_PAYMENT_REFERENCE_PREFIX',
    'SUPERANNUATION_RATE',
    'STANDARD_HOURS',
    'LEAVE_ENTITLEMENTS',
    'LEAVE_MAPPING',
    'TAX_BRACKETS',
    'PERIOD_DIVISORS'
]

# 4. Validation Checks (Production Safety)
try:
    # Verify critical configuration exists
    assert Config.MONGO_URI, "MongoDB URI must be configured"
    assert Config.SECRET_KEY != 'a_secure_random_key', "Change default secret key"
    
    # Verify payroll constants are valid
    assert SUPERANNUATION_RATE > 0, "Super rate must be positive"
    assert len(TAX_BRACKETS) >= 1, "Tax brackets must be defined"

except (AssertionError, AttributeError) as e:
    raise RuntimeError(f"Invalid configuration: {str(e)}") from e
