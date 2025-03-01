
"""
Application modules package.
Contains modular components for authentication, permissions, and business logic.
"""
import logging

# Configure package logger
logger = logging.getLogger(__name__)

# Import the module_manager to expose it at package level
try:
    from .module_manager import (
        module_manager,
        init_app,
        get_service,
        cleanup
    )
    
    logger.debug("Successfully imported module_manager")
    
except ImportError as e:
    logger.error(f"Failed to import module_manager: {str(e)}")
    
    # Create minimal placeholder to prevent application crash
    class DummyModuleManager:
        """Minimal placeholder for ModuleManager to prevent crashes"""
        def __init__(self):
            self.initialized = False
            self._services = {}
            
        def init_app(self, app):
            """Dummy initialization method"""
            logger.warning("Using dummy module manager - limited functionality available")
            self.initialized = True
            return app
            
        def get_service(self, service_name):
            """Return None for any service request"""
            return self._services.get(service_name)
            
        def cleanup(self):
            """Dummy cleanup method"""
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
