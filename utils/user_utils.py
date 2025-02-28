"""
User Management Utilities
Provides functions for managing user accounts, authentication, and role assignments.
"""

import logging
from bson.objectid import ObjectId
from pymongo.errors import DuplicateKeyError, PyMongoError
from datetime import datetime

# Import required utilities
from .database_utils import get_db
from .auth.auth_utils import hash_password, check_password
from .error_utils import ValidationError, NotFoundError, DatabaseError, AppError

logger = logging.getLogger(__name__)

def create_user(user_data):
    """
    Create a new user in the database.
    
    Args:
        user_data (dict): User data including linking_id, payroll_id, company_id, venue_id, etc.
        
    Returns:
        dict: Created user document
        
    Raises:
        ValidationError: If user data is invalid
        DatabaseError: If database operation fails
    """
    try:
        # Get the database connection
        db = get_db()
        
        # Validate user data
        validate_user_data(user_data)
        
        # Hash the password if provided
        if 'password' in user_data:
            user_data['password'] = hash_password(user_data['password'])
        
        # Add creation timestamp
        user_data['created_at'] = datetime.utcnow()
        
        # Default permissions if not provided
        if 'permissions' not in user_data:
            user_data['permissions'] = []
            
        # Insert the user
        result = db.business_users.insert_one(user_data)
        
        # Return the created user
        created_user = db.business_users.find_one({'_id': result.inserted_id})
        
        # Remove sensitive data before returning
        if created_user and 'password' in created_user:
            created_user.pop('password', None)
            
        return created_user
    
    except DuplicateKeyError:
        logger.error(f"User with linking_id {user_data.get('linking_id')} or payroll_id {user_data.get('payroll_id')} already exists")
        raise ValidationError(f"User with linking_id {user_data.get('linking_id')} or payroll_id {user_data.get('payroll_id')} already exists")
    
    except PyMongoError as e:
        logger.error(f"Database error creating user: {str(e)}")
        raise DatabaseError(f"Failed to create user: {str(e)}")
    
    except Exception as e:
        logger.error(f"Unexpected error creating user: {str(e)}")
        raise AppError(f"Unexpected error: {str(e)}")

def get_user_by_id(user_id, id_type='_id'):
    """
    Get a user by their ID. The ID can be MongoDB _id, linking_id, or payroll_id.
    
    Args:
        user_id (str): The ID value to search for
        id_type (str): The type of ID ('_id', 'linking_id', or 'payroll_id')
        
    Returns:
        dict: User document
        
    Raises:
        NotFoundError: If user not found
        ValidationError: If id_type is invalid
        DatabaseError: If database operation fails
    """
    try:
        db = get_db()
        
        # Create query based on ID type
        if id_type == '_id':
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str) and ObjectId.is_valid(user_id):
                user_id = ObjectId(user_id)
            query = {'_id': user_id}
        elif id_type in ['linking_id', 'payroll_id']:
            query = {id_type: user_id}
        else:
            raise ValidationError(f"Invalid id_type: {id_type}. Must be '_id', 'linking_id', or 'payroll_id'")
        
        # Get user from business_users collection
        user = db.business_users.find_one(query)
        
        if not user:
            raise NotFoundError(f"User with {id_type} {user_id} not found")
        
        # Remove sensitive data
        if 'password' in user:
            user.pop('password', None)
            
        return user
    
    except NotFoundError:
        raise
    
    except ValidationError:
        raise
    
    except PyMongoError as e:
        logger.error(f"Database error getting user: {str(e)}")
        raise DatabaseError(f"Failed to get user: {str(e)}")
    
    except Exception as e:
        logger.error(f"Unexpected error getting user: {str(e)}")
        raise AppError(f"Unexpected error: {str(e)}")

def update_user(user_id, update_data, id_type='_id'):
    """
    Update a user's information.
    
    Args:
        user_id (str): The ID value to search for
        update_data (dict): Data to update
        id_type (str): The type of ID ('_id', 'linking_id', or 'payroll_id')
        
    Returns:
        dict: Updated user document
        
    Raises:
        NotFoundError: If user not found
        ValidationError: If update data is invalid
        DatabaseError: If database operation fails
    """
    try:
        db = get_db()
        
        # Create query based on ID type
        if id_type == '_id':
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str) and ObjectId.is_valid(user_id):
                user_id = ObjectId(user_id)
            query = {'_id': user_id}
        elif id_type in ['linking_id', 'payroll_id']:
            query = {id_type: user_id}
        else:
            raise ValidationError(f"Invalid id_type: {id_type}. Must be '_id', 'linking_id', or 'payroll_id'")
        
        # Check if user exists
        user = db.business_users.find_one(query)
        if not user:
            raise NotFoundError(f"User with {id_type} {user_id} not found")
        
        # Validate update data
        validate_user_data(update_data, update=True)
        
        # Hash password if it's being updated
        if 'password' in update_data:
            update_data['password'] = hash_password(update_data['password'])
        
        # Update timestamp
        update_data['updated_at'] = datetime.utcnow()
        
        # Update the user
        result = db.business_users.update_one(
            query,
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            logger.warning(f"No changes made to user with {id_type} {user_id}")
        
        # Get and return the updated user
        updated_user = db.business_users.find_one(query)
        
        # Remove sensitive data
        if updated_user and 'password' in updated_user:
            updated_user.pop('password', None)
            
        return updated_user
    
    except NotFoundError:
        raise
    
    except ValidationError:
        raise
    
    except DuplicateKeyError:
        logger.error(f"Duplicate key error: {update_data}")
        raise ValidationError(f"Update would create a duplicate entry for unique field")
    
    except PyMongoError as e:
        logger.error(f"Database error updating user: {str(e)}")
        raise DatabaseError(f"Failed to update user: {str(e)}")
    
    except Exception as e:
        logger.error(f"Unexpected error updating user: {str(e)}")
        raise AppError(f"Unexpected error: {str(e)}")

def delete_user(user_id, id_type='_id'):
    """
    Delete a user from the database.
    
    Args:
        user_id (str): The ID value to search for
        id_type (str): The type of ID ('_id', 'linking_id', or 'payroll_id')
        
    Returns:
        bool: True if deleted successfully
        
    Raises:
        NotFoundError: If user not found
        ValidationError: If id_type is invalid
        DatabaseError: If database operation fails
    """
    try:
        db = get_db()
        
        # Create query based on ID type
        if id_type == '_id':
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str) and ObjectId.is_valid(user_id):
                user_id = ObjectId(user_id)
            query = {'_id': user_id}
        elif id_type in ['linking_id', 'payroll_id']:
            query = {id_type: user_id}
        else:
            raise ValidationError(f"Invalid id_type: {id_type}. Must be '_id', 'linking_id', or 'payroll_id'")
        
        # Check if user exists
        user = db.business_users.find_one(query)
        if not user:
            raise NotFoundError(f"User with {id_type} {user_id} not found")
        
        # Delete the user
        result = db.business_users.delete_one(query)
        
        if result.deleted_count == 0:
            logger.warning(f"User with {id_type} {user_id} could not be deleted")
            return False
        
        return True
    
    except NotFoundError:
        raise
    
    except ValidationError:
        raise
    
    except PyMongoError as e:
        logger.error(f"Database error deleting user: {str(e)}")
        raise DatabaseError(f"Failed to delete user: {str(e)}")
    
    except Exception as e:
        logger.error(f"Unexpected error deleting user: {str(e)}")
        raise AppError(f"Unexpected error: {str(e)}")

def get_all_users(query=None, skip=0, limit=100, sort_by='created_at', sort_order=-1):
    """
    Get all users with optional filtering, pagination, and sorting.
    
    Args:
        query (dict, optional): Query filter. Defaults to None.
        skip (int, optional): Number of records to skip. Defaults to 0.
        limit (int, optional): Maximum number of records to return. Defaults to 100.
        sort_by (str, optional): Field to sort by. Defaults to 'created_at'.
        sort_order (int, optional): Sort order (1 for ascending, -1 for descending). Defaults to -1.
        
    Returns:
        list: List of user documents
        
    Raises:
        DatabaseError: If database operation fails
    """
    try:
        db = get_db()
        
        # Use empty query if none provided
        query = query or {}
        
        # Get users with pagination and sorting
        users = list(db.business_users.find(query)
                    .sort(sort_by, sort_order)
                    .skip(skip)
                    .limit(limit))
        
        # Remove sensitive data
        for user in users:
            if 'password' in user:
                user.pop('password', None)
        
        return users
    
    except PyMongoError as e:
        logger.error(f"Database error getting users: {str(e)}")
        raise DatabaseError(f"Failed to get users: {str(e)}")
    
    except Exception as e:
        logger.error(f"Unexpected error getting users: {str(e)}")
        raise AppError(f"Unexpected error: {str(e)}")

def validate_user_data(user_data, update=False):
    """
    Validate user data for creation or update.
    
    Args:
        user_data (dict): User data to validate
        update (bool, optional): Whether this is an update operation. Defaults to False.
        
    Raises:
        ValidationError: If data is invalid
    """
    # For create operations, these fields are required
    if not update:
        required_fields = ['linking_id', 'payroll_id', 'company_id', 'venue_id', 'work_area_id']
        for field in required_fields:
            if field not in user_data:
                raise ValidationError(f"Missing required field: {field}")
    
    # Validate linking_id format if provided (e.g., EMP-2976-3088-308020)
    if 'linking_id' in user_data:
        linking_id = user_data['linking_id']
        if not isinstance(linking_id, str) or not linking_id.startswith('EMP-'):
            raise ValidationError("Invalid linking_id format. Must start with 'EMP-' followed by numbers with hyphens")
    
    # Validate payroll_id format if provided (e.g., DK-308020)
    if 'payroll_id' in user_data:
        payroll_id = user_data['payroll_id']
        if not isinstance(payroll_id, str) or not (payroll_id.startswith('DK-') or 
                                                 payroll_id.startswith('DB-') or
                                                 payroll_id.startswith('DR-') or
                                                 payroll_id.startswith('DV-')):
            raise ValidationError("Invalid payroll_id format. Must start with 'DK-', 'DB-', 'DR-', or 'DV-' followed by numbers")
    
    # Validate role_id if provided (e.g., BOH-EXE-207)
    if 'role_id' in user_data:
        role_id = user_data['role_id']
        if not isinstance(role_id, str) or not (role_id.startswith('BOH-') or 
                                             role_id.startswith('FOH-') or
                                             role_id.startswith('ADM-') or
                                             role_id.startswith('GSH-')):
            raise ValidationError("Invalid role_id format. Must start with 'BOH-', 'FOH-', 'ADM-', or 'GSH-' followed by role category and number")
    
    # Validate work_email if provided
    if 'work_email' in user_data:
        email = user_data['work_email']
        # Simple email validation
        if not isinstance(email, str) or '@' not in email or '.' not in email:
            raise ValidationError("Invalid email format")
    
    # Validate password if provided
    if 'password' in user_data:
        password = user_data['password']
        if not isinstance(password, str) or len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long")
    
    return True

def authenticate_user(payroll_id, password):
    """
    Authenticate a user by payroll_id and password.
    
    Args:
        payroll_id (str): User payroll_id (e.g., DK-308020)
        password (str): User password
        
    Returns:
        dict: User document if authenticated, None otherwise
        
    Raises:
        DatabaseError: If database operation fails
    """
    try:
        db = get_db()
        
        # Find the user by payroll_id
        user = db.business_users.find_one({'payroll_id': payroll_id})
        
        if not user:
            logger.warning(f"Authentication failed: User with payroll_id {payroll_id} not found")
            return None
        
        # Check the password
        if not check_password(password, user['password']):
            logger.warning(f"Authentication failed: Invalid password for user {payroll_id}")
            return None
        
        # Update last login timestamp
        db.business_users.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': datetime.utcnow()}}
        )
        
        # Remove sensitive data
        user.pop('password', None)
        
        return user
    
    except PyMongoError as e:
        logger.error(f"Database error during authentication: {str(e)}")
        raise DatabaseError(f"Authentication failed due to database error: {str(e)}")
    
    except Exception as e:
        logger.error(f"Unexpected error during authentication: {str(e)}")
        raise AppError(f"Unexpected error: {str(e)}")

def get_user_roles(user_id, id_type='_id'):
    """
    Get a user's role information (role_id and role_name).
    
    Args:
        user_id (str): The ID value to search for
        id_type (str): The type of ID ('_id', 'linking_id', or 'payroll_id')
        
    Returns:
        dict: Dictionary containing role_id and role_name
        
    Raises:
        NotFoundError: If user not found
        ValidationError: If id_type is invalid
        DatabaseError: If database operation fails
    """
    try:
        db = get_db()
        
        # Get the user
        user = get_user_by_id(user_id, id_type)
        
        # Extract role information
        role_info = {
            'role_id': user.get('role_id'),
            'role_name': user.get('role_name')
        }
        
        return role_info
    
    except NotFoundError:
        raise
    
    except ValidationError:
        raise
    
    except PyMongoError as e:
        logger.error(f"Database error getting user roles: {str(e)}")
        raise DatabaseError(f"Failed to get user roles: {str(e)}")
    
    except Exception as e:
        logger.error(f"Unexpected error getting user roles: {str(e)}")
        raise AppError(f"Unexpected error: {str(e)}")

def assign_role_to_user(user_id, role_id, role_name, id_type='_id'):
    """
    Assign a role to a user.
    
    Args:
        user_id (str): The ID value to search for
        role_id (str): Role ID (e.g., BOH-EXE-207)
        role_name (str): Role name (e.g., Head Chef)
        id_type (str): The type of ID ('_id', 'linking_id', or 'payroll_id')
        
    Returns:
        dict: Updated user document
        
    Raises:
        NotFoundError: If user not found
        ValidationError: If role is invalid
        DatabaseError: If database operation fails
    """
    try:
        db = get_db()
        
        # Create query based on ID type
        if id_type == '_id':
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str) and ObjectId.is_valid(user_id):
                user_id = ObjectId(user_id)
            query = {'_id': user_id}
        elif id_type in ['linking_id', 'payroll_id']:
            query = {id_type: user_id}
        else:
            raise ValidationError(f"Invalid id_type: {id_type}. Must be '_id', 'linking_id', or 'payroll_id'")
        
        # Check if user exists
        user = db.business_users.find_one(query)
        if not user:
            raise NotFoundError(f"User with {id_type} {user_id} not found")
        
        # Validate role_id format
        if not isinstance(role_id, str) or not (role_id.startswith('BOH-') or 
                                             role_id.startswith('FOH-') or
                                             role_id.startswith('ADM-') or
                                             role_id.startswith('GSH-')):
            raise ValidationError("Invalid role_id format. Must start with 'BOH-', 'FOH-', 'ADM-', or 'GSH-' followed by role category and number")
        
        # Update the user with the new role
        update_data = {
            'role_id': role_id,
            'role_name': role_name,
            'updated_at': datetime.utcnow()
        }
        
        result = db.business_users.update_one(
            query,
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            logger.warning(f"No changes made to user with {id_type} {user_id}")
        
        # Get and return the updated user
        updated_user = db.business_users.find_one(query)
        
        # Remove sensitive data
        if updated_user and 'password' in updated_user:
            updated_user.pop('password', None)
            
        return updated_user
    
    except NotFoundError:
        raise
    
    except ValidationError:
        raise
    
    except PyMongoError as e:
        logger.error(f"Database error assigning role: {str(e)}")
        raise DatabaseError(f"Failed to assign role: {str(e)}")
    
    except Exception as e:
        logger.error(f"Unexpected error assigning role: {str(e)}")
        raise AppError(f"Unexpected error: {str(e)}")

def remove_role_from_user(user_id, id_type='_id'):
    """
    Remove a role from a user by setting role_id and role_name to null.
    
    Args:
        user_id (str): The ID value to search for
        id_type (str): The type of ID ('_id', 'linking_id', or 'payroll_id')
        
    Returns:
        dict: Updated user document
        
    Raises:
        NotFoundError: If user not found
        ValidationError: If id_type is invalid
        DatabaseError: If database operation fails
    """
    try:
        db = get_db()
        
        # Create query based on ID type
        if id_type == '_id':
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str) and ObjectId.is_valid(user_id):
                user_id = ObjectId(user_id)
            query = {'_id': user_id}
        elif id_type in ['linking_id', 'payroll_id']:
            query = {id_type: user_id}
        else:
            raise ValidationError(f"Invalid id_type: {id_type}. Must be '_id', 'linking_id', or 'payroll_id'")
        
        # Check if user exists
        user = db.business_users.find_one(query)
        if not user:
            raise NotFoundError(f"User with {id_type} {user_id} not found")
        
        # Remove the role by setting to null
        result = db.business_users.update_one(
            query,
            {'$set': {
                'role_id': None,
                'role_name': None,
                'updated_at': datetime.utcnow()
            }}
        )
        
        if result.modified_count == 0:
            logger.warning(f"No changes made to user with {id_type} {user_id}")
        
        # Get and return the updated user
        updated_user = db.business_users.find_one(query)
        
        # Remove sensitive data
        if updated_user and 'password' in updated_user:
            updated_user.pop('password', None)
            
        return updated_user
    
    except NotFoundError:
        raise
    
    except ValidationError:
        raise
    
    except PyMongoError as e:
        logger.error(f"Database error removing role: {str(e)}")
        raise DatabaseError(f"Failed to remove role: {str(e)}")
    
    except Exception as e:
        logger.error(f"Unexpected error removing role: {str(e)}")
        raise AppError(f"Unexpected error: {str(e)}")
