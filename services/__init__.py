# ------------------------------------------------------------
# services/__init__.py
# ------------------------------------------------------------
"""
Service layer package for business logic abstraction.
This package implements the service layer pattern, separating
business logic from controllers and data access layers.
Contains implementations for authentication, permission management,
and other core application services.
"""
import logging
from typing import Dict, Optional, Any, Tuple

# Import core services and exceptions
from .auth_service import (
    AuthenticationService,
    AuthenticationError,
    init_auth_service
)

from .permission_service import (
    PermissionService,
    PermissionError,
    init_permission_service
)

# Import ID Service
from .id_service import IDService

# Initialize package-level logger
logger = logging.getLogger(__name__)

# Define exported symbols
__all__ = [
    # Authentication services
    'AuthenticationService',
    'AuthenticationError',
    'init_auth_service',
    
    # Permission services
    'PermissionService',
    'PermissionError',
    'init_permission_service',
    
    # ID Service
    'IDService',
    'init_id_service',
    
    # Service provider registration
    'register_services',
    'get_service'
]

# Package metadata
__version__ = '1.0.0'

# Application service registry
_service_registry = {}

def init_id_service(app) -> IDService:
    """
    Initialize and configure the ID Service.
    
    Args:
        app: Flask application instance
        
    Returns:
        IDService: Configured ID service instance
    """
    try:
        # Get MongoDB database from app
        db = app.mongo.db if hasattr(app, 'mongo') and hasattr(app.mongo, 'db') else None
        
        if db is None:
            logger.warning("MongoDB database not available. ID Service may not function correctly.")
            
        # Create and return ID service instance
        id_service = IDService(db)
        logger.info("ID Service initialized successfully")
        
        return id_service
    except Exception as e:
        logger.error(f"Error initializing ID Service: {str(e)}")
        raise

def register_services(app) -> None:
    """
    Register all service implementations with the application.
    
    This function initializes all service implementations and
    registers them with the application context for dependency
    injection throughout the application.
    
    Args:
        app: Flask application instance
    """
    try:
        # Initialize cache client if available
        cache_client = getattr(app, 'redis', None)
        
        # Initialize authentication service
        auth_service = init_auth_service(app)
        _service_registry['auth_service'] = auth_service
        
        # Initialize permission service with cache client
        permission_service = init_permission_service(app, cache_client)
        _service_registry['permission_service'] = permission_service
        
        # Initialize ID service
        id_service = init_id_service(app)
        _service_registry['id_service'] = id_service
        
        # Store ID service directly in app for backward compatibility
        app.config['ID_SERVICE'] = id_service
        
        logger.info("All services registered successfully")
    except Exception as e:
        logger.error(f"Error registering services: {str(e)}")
        raise

def get_service(service_name: str) -> Optional[Any]:
    """
    Get a service implementation by name.
    
    Args:
        service_name: Name of the service to retrieve
    
    Returns:
        Service implementation or None if not found
    """
    return _service_registry.get(service_name)
