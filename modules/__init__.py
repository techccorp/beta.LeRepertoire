"""
Application modules package.
Contains modular components for authentication, permissions, and business logic.
"""
import logging
import traceback

# Configure package logger
logger = logging.getLogger(__name__)

# Import the module_manager to expose it at package level
try:
    # Use a direct import to avoid potential circular issues
    from .module_manager import (
        module_manager,
        init_app,
        get_service,
        cleanup
    )
    
    logger.debug("Successfully imported module_manager")
    
except ImportError as e:
    logger.error(f"Failed to import module_manager: {str(e)}")
    logger.debug(f"Import error details: {traceback.format_exc()}")
    
    # Create minimal placeholder to prevent application crash
    class DummyModuleManager:
        """Minimal placeholder for ModuleManager to prevent crashes"""
        def __init__(self):
            self.initialized = False
            self._services = {}
            logger.warning("Using dummy module manager - limited functionality available")
            
        def init_app(self, app):
            """Dummy initialization method"""
            logger.warning("Using dummy module manager init_app")
            self.initialized = True
            return app
            
        def get_service(self, service_name):
            """Return None for any service request"""
            logger.warning(f"Dummy get_service called for {service_name}")
            return self._services.get(service_name)
            
        def cleanup(self):
            """Dummy cleanup method"""
            logger.warning("Dummy cleanup called")
            self.initialized = False
            self._services.clear()
    
    # Create dummy instance if real one couldn't be imported
    module_manager = DummyModuleManager()
    init_app = module_manager.init_app
    get_service = module_manager.get_service
    cleanup = module_manager.cleanup
    
    logger.warning("Created fallback module_manager due to import error")

# Define package exports
__all__ = [
    'module_manager',
    'init_app',
    'get_service',
    'cleanup'
]
