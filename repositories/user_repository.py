# ------------------------------------------------------------
# repositories/user_repository.py
# ------------------------------------------------------------
"""
User repository implementing the repository pattern.
Provides data access methods for user-related operations.
"""
from typing import Dict, Optional, List, Any, Union
import logging
from datetime import datetime, timedelta
import secrets
from bson import ObjectId
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.errors import PyMongoError

logger = logging.getLogger(__name__)

class UserRepository:
    """
    Repository for user data access operations.
    
    Features:
    - CRUD operations for users
    - Query methods
    - Password reset token management
    - Business-specific user queries
    """
    
    def __init__(self, db: Database):
        """
        Initialize the User Repository.
        
        Args:
            db: MongoDB database instance
        """
        self.db = db
        self.users_collection = db.business_users
        self.reset_tokens_collection = db.password_reset_tokens
    
    def find_by_id(self, user_id: Union[str, ObjectId]) -> Optional[Dict]:
        """
        Find a user by MongoDB ID.
        
        Args:
            user_id: User's MongoDB ID
            
        Returns:
            Dict: User document or None if not found
        """
        try:
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str):
                obj_id = ObjectId(user_id)
            else:
                obj_id = user_id
            
            # Find user
            return self.users_collection.find_one({"_id": obj_id})
            
        except (PyMongoError, ValueError) as e:
            logger.error(f"Error finding user by ID: {str(e)}")
            return None
    
    def find_by_payroll_id(self, payroll_id: str) -> Optional[Dict]:
        """
        Find a user by payroll ID.
        
        Args:
            payroll_id: User's payroll ID
            
        Returns:
            Dict: User document or None if not found
        """
        try:
            return self.users_collection.find_one({"payroll_id": payroll_id})
        except PyMongoError as e:
            logger.error(f"Error finding user by payroll ID: {str(e)}")
            return None
    
    def find_by_email(self, email: str) -> Optional[Dict]:
        """
        Find a user by email address.
        
        Args:
            email: User's email address
            
        Returns:
            Dict: User document or None if not found
        """
        try:
            return self.users_collection.find_one({"work_email": email})
        except PyMongoError as e:
            logger.error(f"Error finding user by email: {str(e)}")
            return None
    
    def find_by_linking_id(self, linking_id: str) -> Optional[Dict]:
        """
        Find a user by linking ID.
        
        Args:
            linking_id: User's linking ID
            
        Returns:
            Dict: User document or None if not found
        """
        try:
            return self.users_collection.find_one({"linking_id": linking_id})
        except PyMongoError as e:
            logger.error(f"Error finding user by linking ID: {str(e)}")
            return None
    
    def find_by_business(self, business_id: str, active_only: bool = True) -> List[Dict]:
        """
        Find users in a specific business.
        
        Args:
            business_id: Business ID
            active_only: Only return active users
            
        Returns:
            List[Dict]: List of user documents
        """
        try:
            query = {"company_id": business_id}
            
            if active_only:
                query["status"] = {"$ne": "inactive"}
            
            return list(self.users_collection.find(query))
        except PyMongoError as e:
            logger.error(f"Error finding users by business: {str(e)}")
            return []
    
    def find_by_venue(self, venue_id: str, active_only: bool = True) -> List[Dict]:
        """
        Find users in a specific venue.
        
        Args:
            venue_id: Venue ID
            active_only: Only return active users
            
        Returns:
            List[Dict]: List of user documents
        """
        try:
            query = {"venue_id": venue_id}
            
            if active_only:
                query["status"] = {"$ne": "inactive"}
            
            return list(self.users_collection.find(query))
        except PyMongoError as e:
            logger.error(f"Error finding users by venue: {str(e)}")
            return []
    
    def find_by_work_area(self, work_area_id: str, active_only: bool = True) -> List[Dict]:
        """
        Find users in a specific work area.
        
        Args:
            work_area_id: Work area ID
            active_only: Only return active users
            
        Returns:
            List[Dict]: List of user documents
        """
        try:
            query = {"work_area_id": work_area_id}
            
            if active_only:
                query["status"] = {"$ne": "inactive"}
            
            return list(self.users_collection.find(query))
        except PyMongoError as e:
            logger.error(f"Error finding users by work area: {str(e)}")
            return []
    
    def find_by_role(self, role_name: str, business_id: Optional[str] = None) -> List[Dict]:
        """
        Find users with a specific role.
        
        Args:
            role_name: Role name
            business_id: Optional business ID to filter by
            
        Returns:
            List[Dict]: List of user documents
        """
        try:
            query = {"role": role_name, "status": {"$ne": "inactive"}}
            
            if business_id:
                query["company_id"] = business_id
            
            return list(self.users_collection.find(query))
        except PyMongoError as e:
            logger.error(f"Error finding users by role: {str(e)}")
            return []
    
    def create(self, user_data: Dict) -> Optional[str]:
        """
        Create a new user.
        
        Args:
            user_data: User data
            
        Returns:
            str: New user ID or None if creation failed
        """
        try:
            # Ensure created_at is set
            if 'created_at' not in user_data:
                user_data['created_at'] = datetime.utcnow()
            
            # Insert user
            result = self.users_collection.insert_one(user_data)
            
            return str(result.inserted_id) if result.inserted_id else None
        except PyMongoError as e:
            logger.error(f"Error creating user: {str(e)}")
            return None
    
    def update(self, user_id: Union[str, ObjectId], update_data: Dict) -> bool:
        """
        Update a user.
        
        Args:
            user_id: User's MongoDB ID
            update_data: Data to update
            
        Returns:
            bool: True if update succeeded, False otherwise
        """
        try:
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str):
                obj_id = ObjectId(user_id)
            else:
                obj_id = user_id
            
            # Add updated_at timestamp
            update_data['updated_at'] = datetime.utcnow()
            
            # Update user
            result = self.users_collection.update_one(
                {"_id": obj_id},
                {"$set": update_data}
            )
            
            return result.modified_count > 0
        except (PyMongoError, ValueError) as e:
            logger.error(f"Error updating user: {str(e)}")
            return False
    
    def update_last_login(self, user_id: Union[str, ObjectId], timestamp: datetime) -> bool:
        """
        Update a user's last login timestamp.
        
        Args:
            user_id: User's MongoDB ID
            timestamp: Login timestamp
            
        Returns:
            bool: True if update succeeded, False otherwise
        """
        try:
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str):
                obj_id = ObjectId(user_id)
            else:
                obj_id = user_id
            
            # Update user
            result = self.users_collection.update_one(
                {"_id": obj_id},
                {"$set": {"last_login": timestamp}}
            )
            
            return result.modified_count > 0
        except (PyMongoError, ValueError) as e:
            logger.error(f"Error updating user last login: {str(e)}")
            return False
    
    def update_password(self, user_id: Union[str, ObjectId], hashed_password: str) -> bool:
        """
        Update a user's password.
        
        Args:
            user_id: User's MongoDB ID
            hashed_password: New hashed password
            
        Returns:
            bool: True if update succeeded, False otherwise
        """
        try:
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str):
                obj_id = ObjectId(user_id)
            else:
                obj_id = user_id
            
            # Update user
            result = self.users_collection.update_one(
                {"_id": obj_id},
                {
                    "$set": {
                        "password": hashed_password,
                        "password_changed_at": datetime.utcnow()
                    }
                }
            )
            
            return result.modified_count > 0
        except (PyMongoError, ValueError) as e:
            logger.error(f"Error updating user password: {str(e)}")
            return False
    
    def delete(self, user_id: Union[str, ObjectId]) -> bool:
        """
        Delete a user.
        
        Args:
            user_id: User's MongoDB ID
            
        Returns:
            bool: True if deletion succeeded, False otherwise
        """
        try:
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str):
                obj_id = ObjectId(user_id)
            else:
                obj_id = user_id
            
            # Delete user
            result = self.users_collection.delete_one({"_id": obj_id})
            
            return result.deleted_count > 0
        except (PyMongoError, ValueError) as e:
            logger.error(f"Error deleting user: {str(e)}")
            return False
    
    def deactivate(self, user_id: Union[str, ObjectId]) -> bool:
        """
        Deactivate a user.
        
        Args:
            user_id: User's MongoDB ID
            
        Returns:
            bool: True if deactivation succeeded, False otherwise
        """
        try:
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str):
                obj_id = ObjectId(user_id)
            else:
                obj_id = user_id
            
            # Deactivate user
            result = self.users_collection.update_one(
                {"_id": obj_id},
                {
                    "$set": {
                        "status": "inactive",
                        "deactivated_at": datetime.utcnow()
                    }
                }
            )
            
            return result.modified_count > 0
        except (PyMongoError, ValueError) as e:
            logger.error(f"Error deactivating user: {str(e)}")
            return False
    
    def reactivate(self, user_id: Union[str, ObjectId]) -> bool:
        """
        Reactivate a user.
        
        Args:
            user_id: User's MongoDB ID
            
        Returns:
            bool: True if reactivation succeeded, False otherwise
        """
        try:
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str):
                obj_id = ObjectId(user_id)
            else:
                obj_id = user_id
            
            # Reactivate user
            result = self.users_collection.update_one(
                {"_id": obj_id},
                {
                    "$set": {
                        "status": "active",
                        "reactivated_at": datetime.utcnow()
                    },
                    "$unset": {
                        "deactivated_at": ""
                    }
                }
            )
            
            return result.modified_count > 0
        except (PyMongoError, ValueError) as e:
            logger.error(f"Error reactivating user: {str(e)}")
            return False
    
    def assign_to_business(self, user_id: Union[str, ObjectId], business_id: str) -> bool:
        """
        Assign a user to a business.
        
        Args:
            user_id: User's MongoDB ID
            business_id: Business ID
            
        Returns:
            bool: True if assignment succeeded, False otherwise
        """
        try:
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str):
                obj_id = ObjectId(user_id)
            else:
                obj_id = user_id
            
            # Update user
            result = self.users_collection.update_one(
                {"_id": obj_id},
                {"$set": {"company_id": business_id}}
            )
            
            return result.modified_count > 0
        except (PyMongoError, ValueError) as e:
            logger.error(f"Error assigning user to business: {str(e)}")
            return False
    
    def assign_to_venue(self, user_id: Union[str, ObjectId], venue_id: str) -> bool:
        """
        Assign a user to a venue.
        
        Args:
            user_id: User's MongoDB ID
            venue_id: Venue ID
            
        Returns:
            bool: True if assignment succeeded, False otherwise
        """
        try:
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str):
                obj_id = ObjectId(user_id)
            else:
                obj_id = user_id
            
            # Update user
            result = self.users_collection.update_one(
                {"_id": obj_id},
                {"$set": {"venue_id": venue_id}}
            )
            
            return result.modified_count > 0
        except (PyMongoError, ValueError) as e:
            logger.error(f"Error assigning user to venue: {str(e)}")
            return False
    
    def assign_to_work_area(self, user_id: Union[str, ObjectId], work_area_id: str) -> bool:
        """
        Assign a user to a work area.
        
        Args:
            user_id: User's MongoDB ID
            work_area_id: Work area ID
            
        Returns:
            bool: True if assignment succeeded, False otherwise
        """
        try:
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str):
                obj_id = ObjectId(user_id)
            else:
                obj_id = user_id
            
            # Update user
            result = self.users_collection.update_one(
                {"_id": obj_id},
                {"$set": {"work_area_id": work_area_id}}
            )
            
            return result.modified_count > 0
        except (PyMongoError, ValueError) as e:
            logger.error(f"Error assigning user to work area: {str(e)}")
            return False
    
    def create_password_reset_token(self, user_id: Union[str, ObjectId]) -> Optional[str]:
        """
        Create a password reset token for a user.
        
        Args:
            user_id: User's MongoDB ID
            
        Returns:
            str: Reset token or None if creation failed
        """
        try:
            # Convert string ID to ObjectId if needed
            if isinstance(user_id, str):
                obj_id = ObjectId(user_id)
            else:
                obj_id = user_id
            
            # Generate token
            token = secrets.token_urlsafe(64)
            
            # Create token document
            token_doc = {
                'user_id': str(obj_id),
                'token': token,
                'created_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(hours=24),
                'used': False
            }
            
            # Store in database
            self.reset_tokens_collection.insert_one(token_doc)
            
            return token
        except (PyMongoError, ValueError) as e:
            logger.error(f"Error creating password reset token: {str(e)}")
            return None
    
    def verify_password_reset_token(self, token: str) -> Optional[Dict]:
        """
        Verify a password reset token.
        
        Args:
            token: Password reset token
            
        Returns:
            Dict: Token data or None if invalid
        """
        try:
            # Find token
            token_doc = self.reset_tokens_collection.find_one({
                'token': token,
                'used': False,
                'expires_at': {'$gt': datetime.utcnow()}
            })
            
            return token_doc
        except PyMongoError as e:
            logger.error(f"Error verifying password reset token: {str(e)}")
            return None
    
    def clear_password_reset_token(self, token: str) -> bool:
        """
        Mark a password reset token as used.
        
        Args:
            token: Password reset token
            
        Returns:
            bool: True if update succeeded, False otherwise
        """
        try:
            # Update token
            result = self.reset_tokens_collection.update_one(
                {'token': token},
                {'$set': {'used': True, 'used_at': datetime.utcnow()}}
            )
            
            return result.modified_count > 0
        except PyMongoError as e:
            logger.error(f"Error clearing password reset token: {str(e)}")
            return False
    
    def count_users_by_business(self, business_id: str, active_only: bool = True) -> int:
        """
        Count users in a business.
        
        Args:
            business_id: Business ID
            active_only: Only count active users
            
        Returns:
            int: Number of users
        """
        try:
            query = {"company_id": business_id}
            
            if active_only:
                query["status"] = {"$ne": "inactive"}
            
            return self.users_collection.count_documents(query)
        except PyMongoError as e:
            logger.error(f"Error counting users by business: {str(e)}")
            return 0
    
    def count_users_by_venue(self, venue_id: str, active_only: bool = True) -> int:
        """
        Count users in a venue.
        
        Args:
            venue_id: Venue ID
            active_only: Only count active users
            
        Returns:
            int: Number of users
        """
        try:
            query = {"venue_id": venue_id}
            
            if active_only:
                query["status"] = {"$ne": "inactive"}
            
            return self.users_collection.count_documents(query)
        except PyMongoError as e:
            logger.error(f"Error counting users by venue: {str(e)}")
            return 0
    
    def count_users_by_work_area(self, work_area_id: str, active_only: bool = True) -> int:
        """
        Count users in a work area.
        
        Args:
            work_area_id: Work area ID
            active_only: Only count active users
            
        Returns:
            int: Number of users
        """
        try:
            query = {"work_area_id": work_area_id}
            
            if active_only:
                query["status"] = {"$ne": "inactive"}
            
            return self.users_collection.count_documents(query)
        except PyMongoError as e:
            logger.error(f"Error counting users by work area: {str(e)}")
            return 0
