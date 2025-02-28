"""
__init__.py for routes/auth/

Registers authentication blueprints and validates schema compatibility during initialization.
"""

import logging
from flask import Flask
from typing import NoReturn

# Configure logging
logger = logging.getLogger(__name__)

def register_auth_routes(app: Flask) -> None:
    """
    Registers authentication blueprints with schema compatibility checks.
    
    Enhanced with:
    - Schema version validation
    - Blueprint URL prefix configuration
    - Detailed error reporting
    
    Blueprints:
      - auth: /auth/* endpoints
      - permission_manager: /auth/permissions/* endpoints
    """
    try:
        # First validate schema compatibility
        _validate_schema_compatibility(app)
        
        # Import blueprints after successful validation
        from .auth_routes import auth
        from .permissions_manager import permission_manager

        # Register with URL prefixes
        app.register_blueprint(auth, url_prefix='/auth')
        app.register_blueprint(
            permission_manager, 
            url_prefix='/auth/permissions'
        )

        logger.info("Auth routes registered with schema version %s", 
                   app.config.get('SCHEMA_VERSION', '1.0'))

    except ImportError as imp_err:
        logger.critical("Blueprint import failed: %s", imp_err, exc_info=True)
        raise
    except Exception as reg_err:
        logger.error("Blueprint registration failed: %s", reg_err, exc_info=True)
        raise

def _validate_schema_compatibility(app: Flask) -> NoReturn:
    """Validate required schema fields exist in MongoDB collection"""
    required_fields = {
        'business_users': [
            'payroll_id', 
            'company_id',
            'role_name',
            'work_email',
            'password'
        ]
    }
    
    try:
        db = app.mongo.db
        for collection, fields in required_fields.items():
            if collection not in db.list_collection_names():
                raise ValueError(f"Missing collection: {collection}")
                
            sample_doc = db[collection].find_one()
            if not sample_doc:
                continue
                
            missing = [field for field in fields if field not in sample_doc]
            if missing:
                raise ValueError(
                    f"Collection {collection} missing fields: {missing}"
                )
                
    except Exception as e:
        logger.critical("Schema validation failed: %s", str(e))
        raise

__all__ = ["register_auth_routes"]
