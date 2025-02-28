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
    
    # Service provider registration
    'register_services',
    'get_service'
]

# Package metadata
__version__ = '1.0.0'

# Application service registry
_service_registry = {}

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
