# --------------------------------------#
#         models/__init__.py            #
# --------------------------------------#
"""
Models package for database entity representations.
Provides a unified interface to access all models and database operations.
"""
import logging
from datetime import datetime
from flask import current_app, g
from bson import ObjectId

# Import database utilities
from .db import (
    get_db, 
    get_search_db, 
    get_collection,
    get_db_connection,
    execute_transaction,
    close_db,
    register_teardown
)

# Import models
from .users_models import BusinessUser

# Initialize package-level logger
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------#
#  Helper functions for user operations with proper implementations
# ---------------------------------------------------------------#

def find_user_in_business(query):
    """
    Find a user in the business users collection based on a raw query.
    
    Args:
        query (dict): Dictionary representing the MongoDB query.
    
    Returns:
        list: List of matching BusinessUser documents
    """
    try:
        # Try MongoEngine query if available
        try:
            return BusinessUser.objects(__raw__=query)
        except Exception:
            # Fallback to direct MongoDB query
            db = get_db()
            return list(db.business_users.find(query))
    except Exception as e:
        logger.error(f"Error finding user in business: {str(e)}")
        return []

def assign_role_to_user(user_id, business_id, role_name, override_data=None):
    """
    Assign a role to a user with updated role information.
    
    Args:
        user_id (str): The identifier of the user.
        business_id (str): The business/company identifier.
        role_name (str): The role to assign.
        override_data (dict, optional): Optional additional data. Defaults to None.
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        db = get_db()
        
        # Support both string ID and ObjectId
        user_query = {"_id": user_id}
        if isinstance(user_id, str) and len(user_id) == 24:
            try:
                object_id = ObjectId(user_id)
                user_query = {"$or": [{"_id": user_id}, {"_id": object_id}]}
            except:
                # If not a valid ObjectId, keep original query
                pass
                
        # Alternative identifiers if _id not found
        alt_query = {
            "$or": [
                user_query,
                {"linking_id": user_id},
                {"payroll_id": user_id}
            ]
        }
        
        # Get role details if role_id format
        role_details = None
        if role_name and role_name.count('-') == 2:  # Format like "BOH-EXE-207"
            try:
                # Query role_ids collection to get role details
                role_details = get_role_details(db, role_name)
            except Exception as e:
                logger.warning(f"Could not get role details: {str(e)}")
        
        # Prepare update data
        update_data = {
            "role": role_name,
            "role_id": role_name if role_name.count('-') == 2 else None,
            "company_id": business_id,
            "updated_at": datetime.utcnow()
        }
        
        # Add role details if available
        if role_details:
            update_data["role_name"] = role_details.get("role")
        
        # Add override data if provided
        if override_data:
            update_data["override_data"] = override_data
        
        # Update user record
        result = db.business_users.update_one(
            alt_query,
            {"$set": update_data}
        )
        
        success = result.modified_count > 0
        
        if success:
            logger.info(f"Role '{role_name}' assigned to user '{user_id}' for business '{business_id}'")
        else:
            logger.warning(f"Failed to assign role to user '{user_id}': User not found")
            
        return success
    except Exception as e:
        logger.error(f"Error assigning role to user: {str(e)}")
        return False

def update_user_override(user_id, business_id, override_dict):
    """
    Update user override data with proper error handling.
    
    Args:
        user_id (str): The identifier of the user.
        business_id (str): The business identifier.
        override_dict (dict): Dictionary with override values.
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        db = get_db()
        
        # Support both string ID and ObjectId
        user_query = {"_id": user_id}
        if isinstance(user_id, str) and len(user_id) == 24:
            try:
                object_id = ObjectId(user_id)
                user_query = {"$or": [{"_id": user_id}, {"_id": object_id}]}
            except:
                # If not a valid ObjectId, keep original query
                pass
        
        # Alternative identifiers if _id not found
        alt_query = {
            "$or": [
                user_query,
                {"linking_id": user_id},
                {"payroll_id": user_id}
            ]
        }
        
        # Add business ID to query if provided
        if business_id:
            alt_query["company_id"] = business_id
            
        # Update user's override data
        result = db.business_users.update_one(
            alt_query,
            {
                "$set": {
                    "override_data": override_dict,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        success = result.modified_count > 0
        
        if success:
            logger.info(f"Override data updated for user '{user_id}'")
        else:
            logger.warning(f"Failed to update override data: User not found")
            
        return success
    except Exception as e:
        logger.error(f"Error updating user override: {str(e)}")
        return False

def get_role_details(db, role_id):
    """
    Get role details from role_ids collection.
    
    Args:
        db: MongoDB database
        role_id (str): Role ID (e.g., "BOH-EXE-207")
        
    Returns:
        dict: Role details or None if not found
    """
    if not role_id or len(role_id) < 3:
        return None
    
    try:
        # Extract department code (e.g., "BOH" from "BOH-EXE-207")
        dept_code = role_id.split('-')[0].lower()
        
        # Map department code to collection ID
        dept_mapping = {
            'adm': 'admin_roles',
            'boh': 'boh_roles',
            'foh': 'foh_roles',
            'gsh': 'gsh_roles'
        }
        
        category = dept_mapping.get(dept_code)
        if not category:
            return None
        
        # Find the role collection
        collection = db.role_ids
        if not collection:
            return None
        
        # Find the document for this category
        category_doc = collection.find_one({"_id": category})
        if not category_doc:
            return None
        
        # Search all role types for matching role ID
        for role_type in ['Dept Manager', 'Employee', 'Executive Management', 
                         'Management', 'Senior Management', 'Sub-Dept Manager']:
            if role_type in category_doc:
                for role in category_doc[role_type]:
                    if role.get('role_id') == role_id:
                        return {
                            'role_id': role_id,
                            'role': role.get('role'),
                            'role_type': role_type,
                            'department': dept_code.upper()
                        }
        
        return None
    except Exception as e:
        logger.error(f"Error getting role details: {str(e)}")
        return None

# Define exported symbols
__all__ = [
    # Models
    'BusinessUser',
    
    # Database utilities
    'get_db',
    'get_search_db',
    'get_collection',
    'get_db_connection',
    'execute_transaction',
    'close_db',
    'register_teardown',
    
    # Helper functions
    'find_user_in_business',
    'assign_role_to_user',
    'update_user_override',
    'get_role_details'
]
