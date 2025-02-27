"""
__init__.py for routes/auth/

This module registers all authentication and authorization related blueprints with the Flask application.
It imports blueprints from:
  - auth_routes.py (exposing the 'auth' blueprint)
  - permissions_manager.py (exposing the 'permission_manager' blueprint)

Usage:
    from routes.auth import register_auth_routes
    register_auth_routes(app)
"""
import logging
from flask import Flask

def register_auth_routes(app: Flask) -> None:
    """
    Registers authentication and authorization blueprints with the provided Flask application.
    
    Blueprints imported:
      - auth: Manages authentication endpoints (login, logout, token verification, etc.).
      - permission_manager: Manages permission and role-based access endpoints.
      
    Args:
        app (Flask): The Flask application instance.
        
    Raises:
        ImportError: If any blueprint module fails to import.
        Exception: If an error occurs during blueprint registration.
    """
    try:
        from .auth_routes import auth
        from .permissions_manager import permission_manager
    except ImportError as imp_err:
        logging.error(f"Error importing auth blueprints: {imp_err}")
        raise
    
    try:
        app.register_blueprint(auth)
        app.register_blueprint(permission_manager)
        logging.info("Authentication and authorization blueprints registered successfully.")
    except Exception as reg_err:
        logging.error(f"Error registering auth blueprints: {reg_err}")
        raise

__all__ = ["register_auth_routes"]
