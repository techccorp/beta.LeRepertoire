"""
Authentication manager for the payroll system, integrating with SessionManager and PermissionManager.
"""
import logging
from typing import Dict, Any, Optional, Union
from flask import g, current_app, request, session
import bcrypt
import re
from datetime import datetime

from utils.auth.session_utils import SessionManager
from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class AuthManager:
    """
    Authentication manager for the payroll system.
    
    Features:
    - Integration with SessionManager
    - User authentication against MongoDB
    - Support for both regular and Google authentication
    - Permission verification with PermissionManager
    - Audit logging of auth events
    """
    
    def __init__(self, app=None, session_manager=None, permission_manager=None):
        """
        Initialize the Authentication Manager.
        
        Args:
            app: Flask application instance
            session_manager: Optional SessionManager instance
            permission_manager: Optional PermissionManager instance
        """
        self.app = app
        self.session_manager = session_manager
        self.permission_manager = permission_manager
        
        if app is not None:
            self.init_app(app)
            
    def init_app(self, app):
        """
        Initialize with Flask app instance.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Initialize session manager if not provided
        if self.session_manager is None:
            from utils.auth.session_utils import SessionManager
            self.session_manager = SessionManager(app)
            
        # Initialize permission manager if not provided
        if self.permission_manager is None and hasattr(app, 'permission_manager'):
            self.permission_manager = app.permission_manager
            
    def authenticate_user(self, payroll_id: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate user with payroll ID and password.
        
        Args:
            payroll_id: User's payroll ID (e.g., DK-308020)
            password: User's password
            
        Returns:
            User document if authentication successful, None otherwise
        """
        try:
            # Validate payroll ID format
            if not self._validate_payroll_id(payroll_id):
                logger.warning(f"Invalid payroll ID format: {payroll_id}")
                return None
                
            # Find user in database
            user = current_app.mongo.db.business_users.find_one({
                "payroll_id": payroll_id,
                "status": {"$ne": "inactive"}
            })
            
            if not user:
                logger.warning(f"User not found with payroll ID: {payroll_id}")
                return None
                
            # Check password
            if not self._check_password(user.get('password', ''), password):
                logger.warning(f"Invalid password for payroll ID: {payroll_id}")
                return None
                
            # Authentication successful
            return user
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None
            
    def create_user_session(self, user_data: Dict[str, Any]) -> bool:
        """
        Create a session for the authenticated user.
        
        Args:
            user_data: User document from MongoDB
            
        Returns:
            True if session creation successful, False otherwise
        """
        try:
            # Create session with SessionManager
            self.session_manager.create_session(user_data)
            
            # Update last login timestamp
            current_app.mongo.db.business_users.update_one(
                {"_id": user_data["_id"]},
                {"$set": {"last_login": datetime.utcnow()}}
            )
            
            # Log successful login
            AuditLogger.log_event(
                'user_login',
                user_data.get('payroll_id', 'unknown'),
                user_data.get('company_id', 'N/A'),
                'Successful login',
                ip_address=request.remote_addr
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Session creation error: {str(e)}")
            return False
            
    def end_user_session(self) -> bool:
        """
        End the current user session.
        
        Returns:
            True if session ended successfully, False otherwise
        """
        try:
            # Get user data for logging
            user_data = self.session_manager.get_user_data()
            
            # End session
            self.session_manager.end_session()
            
            # Log logout if user data available
            if user_data:
                AuditLogger.log_event(
                    'user_logout',
                    user_data.get('payroll_id', 'unknown'),
                    user_data.get('business_id', 'N/A'),
                    'User logged out',
                    ip_address=request.remote_addr
                )
                
            return True
            
        except Exception as e:
            logger.error(f"Session end error: {str(e)}")
            return False
            
    def check_permission(self, permission_name: str, context: Optional[Dict] = None) -> bool:
        """
        Check if the current user has the specified permission.
        
        Args:
            permission_name: Name of the permission to check
            context: Optional context data for permission check
            
        Returns:
            True if user has permission, False otherwise
        """
        try:
            # Return False if no permission manager available
            if not self.permission_manager:
                logger.warning("Permission check failed: No permission manager available")
                return False
                
            # Get user data from session
            user_data = self.session_manager.get_user_data()
            if not user_data:
                logger.warning("Permission check failed: No user in session")
                return False
                
            # Prepare context if not provided
            if context is None:
                context = {
                    'business_id': user_data.get('business_id'),
                    'venue_id': user_data.get('venue_id'),
                    'work_area_id': user_data.get('work_area_id')
                }
                
            # Check permission
            return self.permission_manager.check_permission(
                user_data.get('payroll_id'),
                permission_name,
                context
            )
            
        except Exception as e:
            logger.error(f"Permission check error: {str(e)}")
            return False
            
    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """
        Get the current authenticated user data.
        
        Returns:
            User data dictionary or None if not authenticated
        """
        try:
            # Get user data from session
            user_data = self.session_manager.get_user_data()
            if not user_data:
                return None
                
            # Get full user document from database
            user = current_app.mongo.db.business_users.find_one({
                "payroll_id": user_data.get('payroll_id')
            })
            
            return user
            
        except Exception as e:
            logger.error(f"Error getting current user: {str(e)}")
            return None
            
    def is_authenticated(self) -> bool:
        """
        Check if a user is currently authenticated.
        
        Returns:
            True if authenticated, False otherwise
        """
        return self.session_manager.is_authenticated()
        
    def _validate_payroll_id(self, payroll_id: str) -> bool:
        """
        Validate payroll ID format (e.g., DK-308020).
        
        Args:
            payroll_id: Payroll ID to validate
            
        Returns:
            True if valid, False otherwise
        """
        pattern = r'^D[A-Z]-\d{6}$'
        return bool(re.match(pattern, payroll_id))
        
    def _check_password(self, stored_hash: str, password: str) -> bool:
        """
        Check if the provided password matches the stored hash.
        
        Args:
            stored_hash: Stored password hash
            password: Plaintext password to check
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                stored_hash.encode('utf-8')
            )
        except Exception as e:
            logger.error(f"Password check error: {str(e)}")
            return False
            
    def hash_password(self, password: str) -> str:
        """
        Hash a password for storage.
        
        Args:
            password: Plaintext password
            
        Returns:
            Hashed password
        """
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
