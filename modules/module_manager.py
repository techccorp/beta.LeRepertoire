# ------------------------------------------------------------
# modules/module_manager.py
# ------------------------------------------------------------
from typing import Dict, Optional, Any
from flask import Flask
import logging
from .auth import (
    PermissionManager,
    BusinessContextValidator,
    BusinessValidationError
)
from config import Config

logger = logging.getLogger(__name__)

class ModuleManager:
    """
    Manages initialization and lifecycle of application modules.
    
    Handles:
    - Module initialization
    - Database setup
    - Service registration
    - Error handling and logging
    """
    
    def __init__(self):
        self.initialized = False
        self._modules: Dict[str, Any] = {}
        self._services: Dict[str, Any] = {}

    def init_app(self, app: Flask) -> None:
        """
        Initialize all application modules.
        
        Args:
            app: Flask application instance
        
        Raises:
            RuntimeError: If initialization fails
        """
        try:
            if self.initialized:
                logger.warning("ModuleManager already initialized")
                return

            logger.info("Initializing application modules...")

            # Initialize auth module components
            self._init_auth_module(app)

            # Initialize other modules here as needed
            
            self.initialized = True
            logger.info("Module initialization completed successfully")

        except Exception as e:
            logger.critical(f"Failed to initialize modules: {str(e)}")
            raise RuntimeError(f"Module initialization failed: {str(e)}")

    def _init_auth_module(self, app: Flask) -> None:
        """
        Initialize authentication module components.
        
        Args:
            app: Flask application instance
        """
        try:
            # Initialize permission manager
            permission_manager = PermissionManager(app.config['MONGO_CLIENT'][Config.MONGO_DBNAME])
            self._services['permission_manager'] = permission_manager

            # Initialize business validator
            business_validator = BusinessContextValidator(app.config['MONGO_CLIENT'][Config.MONGO_DBNAME])
            self._services['business_validator'] = business_validator

            # Set up database indexes
            def setup_indexes():
                BusinessContextValidator.setup_db_indexes(app.config['MONGO_CLIENT'][Config.MONGO_DBNAME])

            with app.app_context():
                setup_indexes()

            logger.info("Auth module initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize auth module: {str(e)}")
            raise

    def get_service(self, service_name: str) -> Optional[Any]:
        """
        Retrieve an initialized service by name.
        
        Args:
            service_name: Name of the service to retrieve
            
        Returns:
            Service instance if found, None otherwise
        """
        return self._services.get(service_name)

    def cleanup(self) -> None:
        """Cleanup and release resources."""
        try:
            # Cleanup services
            for service in self._services.values():
                if hasattr(service, 'cleanup'):
                    service.cleanup()

            self._services.clear()
            self._modules.clear()
            self.initialized = False
            logger.info("ModuleManager cleanup completed")

        except Exception as e:
            logger.error(f"Error during ModuleManager cleanup: {str(e)}")
            raise

# Create singleton instance
module_manager = ModuleManager()

# Export for convenience
init_app = module_manager.init_app
get_service = module_manager.get_service
cleanup = module_manager.cleanup

__all__ = ['module_manager', 'init_app', 'get_service', 'cleanup']
