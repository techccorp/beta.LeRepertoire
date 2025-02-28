"""
Central configuration exports for the application.
Combines base configuration with payroll constants and database configuration.
"""
# 1. Import Core Configuration
from .base_config import Config

# 2. Import Google OAuth Configuration
from .google_oauth_config import GoogleOAuthConfig, GoogleOAuthConfigError

# 3. Import Payroll Constants
from .payroll_config import (
    DEFAULT_PAYMENT_REFERENCE_PREFIX,
    SUPERANNUATION_RATE,
    STANDARD_HOURS,
    LEAVE_ENTITLEMENTS,
    LEAVE_MAPPING,
    TAX_BRACKETS,
    PERIOD_DIVISORS
)

# 4. Import MongoDB Configuration (if available)
try:
    from .mongoDB_config import (
        MONGO_URI,
        MONGO_DBNAME,
        MONGO_CONNECT_TIMEOUT,
        MONGO_MAX_POOL_SIZE,
        MONGO_SERVER_SELECTION_TIMEOUT,
        COLLECTIONS,
        get_db,
        get_collection,
        init_mongo,
        close_connection
    )
    # Flag to indicate MongoDB configuration is available
    MONGODB_CONFIG_AVAILABLE = True
except ImportError:
    # MongoDB configuration not available, set flag to False
    MONGODB_CONFIG_AVAILABLE = False

# 5. Explicit Exports
__all__ = [
    # Core Configuration
    'Config',
    
    # Google OAuth Configuration
    'GoogleOAuthConfig',
    'GoogleOAuthConfigError',
    
    # Payroll Constants
    'DEFAULT_PAYMENT_REFERENCE_PREFIX',
    'SUPERANNUATION_RATE',
    'STANDARD_HOURS',
    'LEAVE_ENTITLEMENTS',
    'LEAVE_MAPPING',
    'TAX_BRACKETS',
    'PERIOD_DIVISORS',
    
    # MongoDB Configuration
    'MONGODB_CONFIG_AVAILABLE'
]

# Add MongoDB exports if available
if MONGODB_CONFIG_AVAILABLE:
    __all__.extend([
        'MONGO_URI',
        'MONGO_DBNAME',
        'MONGO_CONNECT_TIMEOUT',
        'MONGO_MAX_POOL_SIZE',
        'MONGO_SERVER_SELECTION_TIMEOUT',
        'COLLECTIONS',
        'get_db',
        'get_collection',
        'init_mongo',
        'close_connection'
    ])

# 6. Validation Checks (Production Safety)
def validate_configuration():
    """Validate critical configuration settings."""
    try:
        # Verify critical configuration exists
        if hasattr(Config, 'MONGO_URI') and not Config.MONGO_URI:
            raise RuntimeError("MongoDB URI must be configured")
        
        if hasattr(Config, 'SECRET_KEY') and Config.SECRET_KEY == 'a_secure_random_key':
            raise RuntimeError("Change default secret key")
        
        # Verify payroll constants are valid
        if SUPERANNUATION_RATE <= 0:
            raise RuntimeError("Super rate must be positive")
        
        if len(TAX_BRACKETS) < 1:
            raise RuntimeError("Tax brackets must be defined")
        
        # Validate Google OAuth config
        GoogleOAuthConfig.validate_config()
        
        return True
    except (AssertionError, AttributeError, GoogleOAuthConfigError) as e:
        raise RuntimeError(f"Invalid configuration: {str(e)}") from e

# Run validation if this module is imported directly
validate_configuration()
