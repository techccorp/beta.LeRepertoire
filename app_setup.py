# ------------------------------------------------------------
# app_setup.py
# ------------------------------------------------------------
"""
Application setup module for initializing all components.
Provides a central point for registering services, repositories, and middleware.
"""
import logging
import os
from flask import Flask
from pymongo import MongoClient
import redis

# Import configuration modules - Updated to use the standardized import approach
from config import Config, GoogleOAuthConfig, GoogleOAuthConfigError

# Import database modules
from db.indexes_setup import setup_all_indexes

# Import services
from services.auth_service import init_auth_service
from services.permission_service import init_permission_service

# Import repositories
from repositories.user_repository import UserRepository

# Import authentication modules
from utils.auth.session_manager import init_session_manager
from utils.auth.token_manager import init_token_manager
from utils.auth.mfa import init_mfa_manager

# Import routes
from routes.auth import register_auth_routes

logger = logging.getLogger(__name__)

def setup_logging(app):
    """Set up application logging."""
    log_level = app.config.get('LOG_LEVEL', 'INFO')
    log_format = app.config.get('LOG_FORMAT', 
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, log_level),
        format=log_format
    )
    
    logger.info(f"Logging initialized with level {log_level}")

def setup_database(app):
    """Set up MongoDB database connection."""
    try:
        # Get MongoDB URI from config
        mongo_uri = app.config.get('MONGO_URI', 'mongodb://localhost:27017/')
        db_name = app.config.get('MONGO_DBNAME', 'MyCookBook')
        
        # Create MongoDB client
        client = MongoClient(mongo_uri)
        db = client[db_name]
        
        # Test connection
        client.admin.command('ping')
        
        # Store client and db in app
        app.mongo = type('MongoConnection', (), {'client': client, 'db': db})
        
        logger.info(f"Connected to MongoDB database: {db_name}")
        
        # Set up indexes
        setup_all_indexes(db)
        
        return app.mongo
        
    except Exception as e:
        logger.error(f"Error connecting to MongoDB: {str(e)}")
        raise

def setup_redis(app):
    """Set up Redis connection if configured."""
    try:
        redis_url = app.config.get('REDIS_URL')
        if not redis_url:
            logger.info("Redis not configured, skipping setup")
            return None
            
        # Create Redis client
        redis_client = redis.from_url(redis_url)
        
        # Test connection
        redis_client.ping()
        
        # Store client in app
        app.redis = redis_client
        
        logger.info(f"Connected to Redis: {redis_url}")
        
        return redis_client
        
    except Exception as e:
        logger.warning(f"Error connecting to Redis: {str(e)}")
        logger.warning("Continuing without Redis cache support")
        return None

def setup_repositories(app):
    """Set up repositories."""
    try:
        # Create user repository
        user_repo = UserRepository(app.mongo.db)
        
        # Store repositories in app
        app.user_repository = user_repo
        
        logger.info("Repositories initialized")
        
    except Exception as e:
        logger.error(f"Error setting up repositories: {str(e)}")
        raise

def setup_google_oauth(app):
    """Set up Google OAuth components."""
    try:
        # Validate Google OAuth configuration
        try:
            GoogleOAuthConfig.validate_config()
            
            # Store OAuth configuration in app
            app.config['GOOGLE_CLIENT_ID'] = GoogleOAuthConfig.GOOGLE_CLIENT_ID
            app.config['GOOGLE_CLIENT_SECRET'] = GoogleOAuthConfig.GOOGLE_CLIENT_SECRET
            app.config['GOOGLE_DISCOVERY_URL'] = GoogleOAuthConfig.GOOGLE_DISCOVERY_URL
            app.config['GOOGLE_AUTH_URI'] = GoogleOAuthConfig.GOOGLE_AUTH_URI
            app.config['GOOGLE_TOKEN_URI'] = GoogleOAuthConfig.GOOGLE_TOKEN_URI
            app.config['GOOGLE_REDIRECT_URI'] = GoogleOAuthConfig.GOOGLE_REDIRECT_URI
            app.config['GOOGLE_SCOPES'] = GoogleOAuthConfig.GOOGLE_SCOPES
            
            # Add all OAuth configuration as a dictionary for easy access
            app.config['GOOGLE_OAUTH_CONFIG'] = GoogleOAuthConfig.get_oauth_config()
            
            logger.info("Google OAuth components configured")
            return True
        except GoogleOAuthConfigError as e:
            # In development mode, we'll continue without Google OAuth
            if app.config.get('DEBUG', False):
                logger.warning(f"Google OAuth not configured properly: {str(e)}")
                logger.warning("Google OAuth features will not be available")
                return False
            else:
                # In production, this is a critical error
                raise
            
    except Exception as e:
        logger.error(f"Error setting up Google OAuth: {str(e)}")
        raise

def setup_auth_components(app, redis_client=None):
    """Set up authentication components."""
    try:
        # Initialize session manager
        session_manager = init_session_manager(app, redis_client)
        app.session_manager = session_manager
        logger.info("Session manager initialized")
        
        # Initialize token manager
        token_manager = init_token_manager(app)
        app.token_manager = token_manager
        logger.info("Token manager initialized")
        
        # Initialize MFA manager
        mfa_manager = init_mfa_manager(app)
        app.mfa_manager = mfa_manager
        logger.info("MFA manager initialized")
        
        # Initialize Google OAuth
        setup_google_oauth(app)
        
        # Try to initialize the permission manager
        try:
            # First try modules approach
            from modules.permissionsManager_module import init_permission_manager
            permission_manager = init_permission_manager(app)
            logger.info("Permission Manager initialized from modules package")
        except (ImportError, AttributeError) as e:
            logger.info(f"Permission Manager not available in modules package: {str(e)}")
            
            # Try alternate implementation
            try:
                from services.permission_service import init_permission_service
                permission_manager = init_permission_service(app)
                logger.info("Permission Manager initialized from services package")
            except (ImportError, AttributeError) as e:
                logger.info(f"Permission Manager not available in services package: {str(e)}")
                permission_manager = None
        
        # Register permission manager if initialized
        if permission_manager:
            app.permission_manager = permission_manager
            logger.info("Permission Manager registered with application")
        else:
            logger.warning("No Permission Manager available, permission checks will be disabled")
        
        logger.info("Authentication components initialized")
        
    except Exception as e:
        logger.error(f"Error setting up authentication components: {str(e)}")
        raise

def setup_services(app, redis_client=None):
    """Set up application services."""
    try:
        # Initialize authentication service
        auth_service = init_auth_service(app)
        app.auth_service = auth_service
        logger.info("Authentication service initialized")
        
        # Initialize permission service if not already initialized
        if not hasattr(app, 'permission_manager'):
            try:
                permission_service = init_permission_service(app, redis_client)
                app.permission_service = permission_service
                logger.info("Permission service initialized")
            except (ImportError, AttributeError) as e:
                logger.warning(f"Permission service not available: {str(e)}")
        
        logger.info("Services initialized")
        
    except Exception as e:
        logger.error(f"Error setting up services: {str(e)}")
        raise

def register_routes(app):
    """Register all application routes."""
    try:
        # Import route registration functions
        from routes import register_routes
        register_routes(app)
        
        # Register authentication routes
        register_auth_routes(app)
        
        logger.info("Routes registered")
        
    except Exception as e:
        logger.error(f"Error registering routes: {str(e)}")
        raise

def setup_middleware(app):
    """Set up application middleware."""
    try:
        # Add before_request handlers for authentication and permissions
        @app.before_request
        def update_session_activity():
            """Update session activity on each request."""
            if hasattr(app, 'session_manager'):
                app.session_manager.update_activity()
        
        logger.info("Middleware configured")
        
    except Exception as e:
        logger.error(f"Error setting up middleware: {str(e)}")
        raise

def setup_error_handlers(app):
    """Set up application error handlers."""
    try:
        # Import custom exceptions
        from utils.error_utils import AppError, AuthenticationError, PermissionError, ValidationError, NotFoundError, DatabaseError, handle_error
        from utils.auth.session_manager import SessionExpiredError
        
        # Register error handlers
        @app.errorhandler(AppError)
        def handle_app_error(error):
            return handle_error(error)
        
        @app.errorhandler(AuthenticationError)
        def handle_authentication_error(error):
            return handle_error(error)
        
        @app.errorhandler(PermissionError)
        def handle_permission_error(error):
            return handle_error(error)
        
        @app.errorhandler(ValidationError)
        def handle_validation_error(error):
            return handle_error(error)
        
        @app.errorhandler(NotFoundError)
        def handle_not_found_error(error):
            return handle_error(error)
        
        @app.errorhandler(DatabaseError)
        def handle_database_error(error):
            return handle_error(error)
        
        @app.errorhandler(SessionExpiredError)
        def handle_session_expired(error):
            from flask import jsonify, redirect, url_for, request
            # Clear session
            if hasattr(app, 'session_manager'):
                app.session_manager.end_session()
            
            # Handle API requests differently
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    "success": False,
                    "message": str(error),
                    "code": "SESSION_EXPIRED"
                }), 401
            
            # Redirect to login for browser requests
            return redirect(url_for('auth.login'))
        
        logger.info("Error handlers registered")
        
    except Exception as e:
        logger.error(f"Error setting up error handlers: {str(e)}")
        raise

def cleanup_resources(app):
    """Register cleanup handlers for application resources."""
    try:
        @app.teardown_appcontext
        def close_db_connection(exception=None):
            """Close MongoDB connection on request end."""
            if hasattr(app, 'mongo') and hasattr(app.mongo, 'client'):
                app.mongo.client.close()
        
        logger.info("Resource cleanup handlers registered")
        
    except Exception as e:
        logger.error(f"Error setting up resource cleanup: {str(e)}")
        raise

def setup_app(app):
    """
    Set up all application components.
    
    Args:
        app: Flask application instance
    """
    try:
        with app.app_context():
            # Set up logging first
            setup_logging(app)
            
            # Setup core components
            mongo = setup_database(app)
            redis_client = setup_redis(app)
            
            # Set up repositories
            setup_repositories(app)
            
            # Set up authentication components
            setup_auth_components(app, redis_client)
            
            # Set up services
            setup_services(app, redis_client)
            
            # Register routes
            register_routes(app)
            
            # Set up middleware
            setup_middleware(app)
            
            # Set up error handlers
            setup_error_handlers(app)
            
            # Register cleanup handlers
            cleanup_resources(app)
            
            logger.info("Application setup complete")
            
    except Exception as e:
        logger.error(f"Error setting up application: {str(e)}")
        raise

def create_app(config_object=None):
    """
    Factory function to create and configure a Flask application.
    
    Args:
        config_object: Configuration object or class
        
    Returns:
        Flask: Configured Flask application
    """
    # Create Flask app
    app = Flask(__name__)
    
    # Load default configuration
    app.config.from_object(Config)
    
    # Load additional configuration if provided
    if config_object:
        app.config.from_object(config_object)
    
    # Set up all application components
    setup_app(app)
    
    return app
