# ------------------------------------------------------------
# modules/module_manager.py
# ------------------------------------------------------------
from typing import Dict, Optional, Any
from flask import Flask
import logging
import traceback
from pymongo.errors import OperationFailure

# Import from auth module with proper exception handling
try:
    from .auth import (
        PermissionManager,
        BusinessContextValidator,
        BusinessValidationError
    )
except ImportError as e:
    # Log the error but continue initialization - we'll handle it below
    logging.error(f"Error importing auth components: {str(e)}")

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
            logger.debug(f"Initialization error details: {traceback.format_exc()}")
            raise RuntimeError(f"Module initialization failed: {str(e)}")

    def _init_auth_module(self, app: Flask) -> None:
        """
        Initialize authentication module components.
        
        Args:
            app: Flask application instance
        """
        try:
            # Get database reference
            db = None
            if 'MONGO_CLIENT' in app.config:
                try:
                    # Try to access using client[db_name] indexing
                    db = app.config['MONGO_CLIENT'][Config.MONGO_DBNAME]
                except (TypeError, KeyError):
                    # Fallback to original approach if the above fails
                    pass
                    
            # If still no db, try the app.mongo.db approach
            if db is None:
                db = app.mongo.db if hasattr(app, 'mongo') and hasattr(app.mongo, 'db') else None
                
            if db is None:
                logger.error("Failed to get database reference for auth module")
                raise ValueError("Database reference not available")

            # First check if the classes are available
            if 'BusinessContextValidator' not in globals() or 'PermissionManager' not in globals():
                # Try to import again to handle potential circular imports
                try:
                    from .auth import BusinessContextValidator, PermissionManager
                except ImportError as e:
                    logger.error(f"Failed to import auth components: {str(e)}")
                    raise
                    
            # Initialize business validator (which includes work_area_id validation)
            business_validator = BusinessContextValidator(db)
            self._services['business_validator'] = business_validator

            # Initialize permission manager
            permission_manager = PermissionManager(db)
            self._services['permission_manager'] = permission_manager

            # Set up database indexes with error handling
            try:
                with app.app_context():
                    BusinessContextValidator.setup_db_indexes(db)
            except OperationFailure as e:
                # Log the error but continue initialization
                logger.warning(f"Error setting up indexes: {str(e)}")
                logger.info("Continuing initialization without complete index setup")
            except Exception as e:
                logger.error(f"Unexpected error setting up indexes: {str(e)}")
                # Continue initialization despite index errors
                    
            logger.info("Auth module initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize auth module: {str(e)}")
            logger.debug(f"Auth module initialization error details: {traceback.format_exc()}")
            raise
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
            for service_name, service in self._services.items():
                if hasattr(service, 'cleanup'):
                    try:
                        service.cleanup()
                    except Exception as e:
                        logger.error(f"Error cleaning up service {service_name}: {str(e)}")

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
