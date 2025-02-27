# ------------------------------------------------------------#
#                   routes/__init__.py                   #
# ------------------------------------------------------------#

"""
__init__.py for routes/

This module registers all application route blueprints with the Flask app.
It imports and registers blueprints from submodules (search routes and payroll routes).

Usage:
    from routes import register_routes
    register_routes(app)
"""
import logging
from flask import Flask

def register_routes(app: Flask) -> None:
    """
    Registers all route blueprints with the provided Flask application.
    
    This function imports and registers blueprints from all route modules.
    Currently included:
      - Search routes (from routes/search/__init__.py)
      - Payroll routes (from routes/payroll_routes.py)
      - Authentication routes (from routes/auth/__init__.py)
    
    Args:
        app (Flask): The Flask application instance.
        
    Raises:
        ImportError: If a blueprint module cannot be imported.
        Exception: If an error occurs during blueprint registration.
    """
    # Register search routes
    try:
        from .search import register_search_routes
        register_search_routes(app)
        logging.info("Search routes registered successfully.")
    except ImportError as imp_err:
        logging.error(f"Error importing search routes: {imp_err}")
        raise
    except Exception as reg_err:
        logging.error(f"Error registering search routes: {reg_err}")
        raise
    
    # Register authentication routes
    try:
        from .auth import register_auth_routes
        register_auth_routes(app)
        logging.info("Authentication routes registered successfully.")
    except ImportError as imp_err:
        logging.error(f"Error importing authentication routes: {imp_err}")
        raise
    except Exception as reg_err:
        logging.error(f"Error registering authentication routes: {reg_err}")
        raise
    
    # Register payroll routes
    try:
        from .payroll_routes import payroll
        app.register_blueprint(payroll)
        logging.info("Payroll routes registered successfully.")
    except ImportError as imp_err:
        logging.error(f"Error importing payroll routes: {imp_err}")
        raise
    except Exception as reg_err:
        logging.error(f"Error registering payroll routes: {reg_err}")
        raise
    
    logging.info("All routes registered successfully.")

__all__ = ["register_routes"]
