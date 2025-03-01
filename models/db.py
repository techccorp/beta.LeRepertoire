# ------------------------------------------------------------
# models/db.py
# ------------------------------------------------------------
"""
Database connection utilities for consistent MongoDB access.
Provides centralized functions for database connections and collections.
"""
import logging
from flask import current_app, g
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson.objectid import ObjectId

logger = logging.getLogger(__name__)

def get_db_connection():
    """
    Get a MongoDB client connection with connection pooling.
    Prioritizes existing app.mongo client if available.
    
    Returns:
        MongoClient: MongoDB client instance
    """
    if 'mongo_client' not in g:
        try:
            # First try to use existing client from app.mongo if available
            if hasattr(current_app, 'mongo') and hasattr(current_app.mongo, 'client'):
                g.mongo_client = current_app.mongo.client
                return g.mongo_client
                
            # Otherwise create new connection using URI from config
            mongo_uri = current_app.config.get('MONGO_URI', 'mongodb://localhost:27017/')
            
            # Get connection parameters from config
            connect_params = {
                'serverSelectionTimeoutMS': current_app.config.get('MONGO_SERVER_SELECTION_TIMEOUT', 5000),
                'connectTimeoutMS': current_app.config.get('MONGO_CONNECT_TIMEOUT', 5000),
                'maxPoolSize': current_app.config.get('MONGO_MAX_POOL_SIZE', 100),
                'retryWrites': True,
                'w': 'majority'
            }
            
            # Create client with robust configuration
            g.mongo_client = MongoClient(mongo_uri, **connect_params)
            
        except Exception as e:
            logger.error(f"Error creating MongoDB client: {str(e)}")
            # Final fallback to existing client if creation failed
            if hasattr(current_app, 'mongo') and hasattr(current_app.mongo, 'client'):
                g.mongo_client = current_app.mongo.client
            else:
                raise
    
    return g.mongo_client

def get_db(collection_name=None):
    """
    Get MongoDB database or collection.
    
    Args:
        collection_name (str, optional): Collection name to access. Defaults to None.
        
    Returns:
        Database or Collection: MongoDB database or collection
    """
    try:
        # Try to get from app.mongo.db (as used in app.py)
        if hasattr(current_app, 'mongo') and hasattr(current_app.mongo, 'db'):
            db = current_app.mongo.db
        else:
            # Create connection and get database
            client = get_db_connection()
            db_name = current_app.config.get('MONGO_DBNAME', 'MyCookBook')
            db = client[db_name]
        
        # Return specific collection if requested
        if collection_name:
            return db[collection_name]
        
        return db
    except Exception as e:
        logger.error(f"Error getting database: {str(e)}")
        raise

def get_search_db(collection_name=None):
    """
    Get search database or collection.
    Fallback to main database if search database not configured.
    
    Args:
        collection_name (str, optional): Collection name to access. Defaults to None.
        
    Returns:
        Database or Collection: MongoDB database or collection
    """
    try:
        # Get database name from config
        search_db_name = current_app.config.get('MONGO_SEARCH_DBNAME')
        
        # If no specific search DB configured, use main DB
        if not search_db_name:
            return get_db(collection_name)
        
        # Get client and database
        client = get_db_connection()
        db = client[search_db_name]
        
        # Return collection if requested
        if collection_name:
            return db[collection_name]
        
        return db
    except Exception as e:
        logger.error(f"Error getting search database: {str(e)}")
        # Fallback to main database
        return get_db(collection_name)

def get_collection(collection_name, db_name=None):
    """
    Get a specific MongoDB collection.
    
    Args:
        collection_name (str): Name of the collection
        db_name (str, optional): Database name override. Defaults to None.
        
    Returns:
        Collection: MongoDB collection
    """
    try:
        if db_name:
            # Get specific database
            client = get_db_connection()
            db = client[db_name]
            return db[collection_name]
        else:
            # Use default database
            return get_db(collection_name)
    except Exception as e:
        logger.error(f"Error getting collection '{collection_name}': {str(e)}")
        raise

def execute_transaction(callback, **kwargs):
    """
    Execute a transaction with proper error handling.
    
    Args:
        callback: Function that performs the transaction operations
        **kwargs: Additional arguments for the callback
        
    Returns:
        Any: Result of the transaction
    """
    client = get_db_connection()
    
    try:
        with client.start_session() as session:
            return session.with_transaction(
                lambda s: callback(s, **kwargs)
            )
    except Exception as e:
        logger.error(f"Transaction failed: {str(e)}")
        raise

def close_db(e=None):
    """
    Close database connection when request context ends.
    
    Args:
        e: Optional exception that occurred
    """
    client = g.pop('mongo_client', None)
    if client:
        client.close()
        logger.debug("MongoDB connection closed")

def register_teardown(app):
    """
    Register database teardown with Flask app.
    
    Args:
        app: Flask application instance
    """
    @app.teardown_appcontext
    def teardown_db(exception):
        close_db(exception)
