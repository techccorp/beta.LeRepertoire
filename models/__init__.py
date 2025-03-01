# --------------------------------------#
#         models/__init__.py            #
# --------------------------------------#
from .users_models import BusinessUser
from flask import current_app, g

def get_db(app=None):
    """
    Return the database connection. This function is maintained for backward compatibility.
    It attempts to retrieve the PyMongo database instance from current_app.
    
    Args:
        app: Optional Flask app instance (for backward compatibility).
    
    Returns:
        MongoDB database instance.
    """
    try:
        # Try to get the db from current_app's mongo attribute.
        return current_app.mongo.db
    except Exception:
        if app:
            return app.mongo.db
        return current_app.mongo.db

def get_search_db(app=None):
    """
    Return the search database connection for backward compatibility.
    
    Args:
        app: Optional Flask app instance.
    
    Returns:
        MongoDB database instance.
    """
    return get_db(app)

def register_teardown(app):
    """
    Register database teardown handlers with Flask app.
    
    Args:
        app: Flask application instance
    """
    @app.teardown_appcontext
    def close_mongo_connection(exception=None):
        """Close any open MongoDB connections at the end of the request."""
        mongo_client = g.pop('mongo_client', None)
        if mongo_client:
            mongo_client.close()
            
    # Log registration of teardown handler
    if app.logger:
        app.logger.info("Registered MongoDB connection teardown handler")
    
    return app

# ---------------------------------------------------------------#
#  Legacy helper functions for user operations (backward compatible)
# ---------------------------------------------------------------#
def find_user_in_business(query):
    """
    Find a user in the business users collection based on a raw query.
    
    Args:
        query: Dictionary representing the MongoDB query.
    
    Returns:
        A QuerySet of BusinessUser documents matching the query.
    """
    return BusinessUser.objects(__raw__=query)

def assign_role_to_user(user_id, business_id, role_name, override_data=None):
    """
    Assign a role to a user. This is a stub for legacy functionality.
    
    Args:
        user_id: The identifier of the user.
        business_id: The business identifier.
        role_name: The role to assign.
        override_data: Optional additional data.
    
    Raises:
        NotImplementedError: To indicate that role assignment logic needs to be implemented.
    """
    raise NotImplementedError("Role assignment logic is not implemented.")

def update_user_override(user_id, business_id, override_dict):
    """
    Update user override data. This is a stub for legacy functionality.
    
    Args:
        user_id: The identifier of the user.
        business_id: The business identifier.
        override_dict: Dictionary with override values.
    
    Raises:
        NotImplementedError: To indicate that override update logic needs to be implemented.
    """
    raise NotImplementedError("User override update logic is not implemented.")

__all__ = [
    'BusinessUser',
    'get_db',
    'get_search_db',
    'register_teardown',
    'find_user_in_business',
    'assign_role_to_user',
    'update_user_override'
]
