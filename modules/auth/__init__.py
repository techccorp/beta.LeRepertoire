"""
Authentication and authorization module.
Handles permission management, business context validation, and user access control.
"""
import logging

# Configure module logger
logger = logging.getLogger(__name__)

# Import components
try:
    from .business_context_validator import (
        BusinessContextValidator,
        BusinessValidationError
    )
    
    from .permission_manager import (
        PermissionManager
    )

except ImportError as e:
    logger.error(f"Failed to import auth components: {str(e)}")
    
    # Create minimal placeholders for critical classes
    class BusinessValidationError(Exception):
        """Placeholder exception for business validation errors"""
        pass
    
    class BusinessContextValidator:
        """Placeholder for BusinessContextValidator"""
        def __init__(self, db):
            self.db = db
            
        @staticmethod
        def setup_db_indexes(db):
            """Placeholder for index setup"""
            logger.warning("Using placeholder BusinessContextValidator - indexes not created")
    
    class PermissionManager:
        """Placeholder for PermissionManager"""
        def __init__(self, db):
            self.db = db

# Define exported symbols
__all__ = [
    'BusinessContextValidator',
    'BusinessValidationError',
    'PermissionManager'
]
