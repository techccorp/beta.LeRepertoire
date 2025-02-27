# ------------------------------------------------------------
# services/auth_service.py
# ------------------------------------------------------------
"""
Authentication service implementing the service layer pattern.
Separates business logic from controllers and data access.
"""
from typing import Dict, Optional, Tuple, Any, List
import logging
from datetime import datetime
from flask import current_app, request, g

from utils.auth.auth_utils import validate_payroll_id, check_password, hash_password
from utils.audit_logger import AuditLogger
from repositories.user_repository import UserRepository

logger = logging.getLogger(__name__)

class AuthenticationError(Exception):
    """Custom exception for authentication errors."""
    def __init__(self, message, code=None, status_code=401):
        self.message = message
        self.code = code or 'AUTH_ERROR'
        self.status_code = status_code
        super().__init__(self.message)

class AuthenticationService:
    """
    Authentication service implementing business logic for authentication flows.
    
    Features:
    - User authentication
    - Token management
    - Password management
    - Multi-factor authentication
    - Session management
    """
    
    def __init__(self, user_repository=None):
        """
        Initialize the Authentication Service.
        
        Args:
            user_repository: Optional user repository for data access
        """
        self.user_repository = user_repository
    
    def authenticate(self, payroll_id: str, password: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Authenticate a user with payroll ID and password.
        
        Args:
            payroll_id: User's payroll ID
            password: User's password
            
        Returns:
            Tuple[bool, Optional[Dict], Optional[str]]: (success, user_data, error_message)
        """
        try:
            # Validate payroll ID format
            if not validate_payroll_id(payroll_id):
                return False, None, "Invalid payroll ID format"
            
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Find user
            user = user_repo.find_by_payroll_id(payroll_id)
            
            if not user:
                logger.warning(f"Authentication failed: User not found with payroll ID {payroll_id}")
                return False, None, "Invalid payroll ID or password"
            
            # Check if user is active
            if user.get('status') == 'inactive':
                logger.warning(f"Authentication failed: User {payroll_id} is inactive")
                return False, None, "Account is inactive or has been disabled"
            
            # Verify password
            if not check_password(user.get('password', ''), password):
                logger.warning(f"Authentication failed: Invalid password for {payroll_id}")
                return False, None, "Invalid payroll ID or password"
            
            # Check if MFA is required
            mfa_required = self._is_mfa_required(user)
            
            # If MFA is required, return success with MFA flag
            if mfa_required:
                return True, user, "mfa_required"
            
            # Create session
            if hasattr(current_app, 'session_manager'):
                session_id, refresh_token = current_app.session_manager.create_session(user)
            
            # Update last login timestamp
            user_repo.update_last_login(user.get('_id'), datetime.utcnow())
            
            # Log successful login
            AuditLogger.log_event(
                'user_login',
                payroll_id,
                user.get('company_id', 'N/A'),
                'Successful login',
                ip_address=request.remote_addr
            )
            
            return True, user, None
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False, None, str(e)
    
    def verify_mfa(self, payroll_id: str, code: str, is_recovery_code: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Verify MFA code for a user.
        
        Args:
            payroll_id: User's payroll ID
            code: MFA code to verify
            is_recovery_code: Whether the code is a recovery code
            
        Returns:
            Tuple[bool, Optional[str]]: (success, error_message)
        """
        try:
            # Check if MFA manager is available
            if not hasattr(current_app, 'mfa_manager'):
                return False, "MFA not configured"
            
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Find user
            user = user_repo.find_by_payroll_id(payroll_id)
            
            if not user:
                logger.warning(f"MFA verification failed: User not found with payroll ID {payroll_id}")
                return False, "User not found"
            
            # Verify code
            if is_recovery_code:
                verified = current_app.mfa_manager.verify_recovery_code(payroll_id, code)
            else:
                verified = current_app.mfa_manager.verify_totp_code(payroll_id, code)
            
            if not verified:
                logger.warning(f"MFA verification failed: Invalid code for {payroll_id}")
                return False, "Invalid verification code"
            
            # Create session
            if hasattr(current_app, 'session_manager'):
                session_id, refresh_token = current_app.session_manager.create_session(user)
            
            # Update last login timestamp
            user_repo.update_last_login(user.get('_id'), datetime.utcnow())
            
            # Log successful MFA verification
            AuditLogger.log_event(
                'mfa_verified',
                payroll_id,
                user.get('company_id', 'N/A'),
                f'MFA verified with {"recovery code" if is_recovery_code else "TOTP"}',
                ip_address=request.remote_addr
            )
            
            return True, None
            
        except Exception as e:
            logger.error(f"MFA verification error: {str(e)}")
            return False, str(e)
    
    def logout(self) -> bool:
        """
        Log out the current user and terminate the session.
        
        Returns:
            bool: True if logout was successful, False otherwise
        """
        try:
            # Check if session manager is available
            if not hasattr(current_app, 'session_manager'):
                return False
            
            # End session
            return current_app.session_manager.end_session(reason='user_logout')
            
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return False
    
    def change_password(self, user_id: str, current_password: str, 
                        new_password: str) -> Tuple[bool, Optional[str]]:
        """
        Change a user's password.
        
        Args:
            user_id: User's MongoDB ID
            current_password: User's current password
            new_password: User's new password
            
        Returns:
            Tuple[bool, Optional[str]]: (success, error_message)
        """
        try:
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Find user
            user = user_repo.find_by_id(user_id)
            
            if not user:
                return False, "User not found"
            
            # Verify current password
            if not check_password(user.get('password', ''), current_password):
                return False, "Current password is incorrect"
            
            # Validate new password
            if len(new_password) < 8:
                return False, "New password must be at least 8 characters long"
            
            # Hash new password
            hashed_password = hash_password(new_password)
            
            # Update password
            success = user_repo.update_password(user_id, hashed_password)
            
            if not success:
                return False, "Failed to update password"
            
            # Log password change
            AuditLogger.log_event(
                'password_changed',
                user.get('payroll_id', 'unknown'),
                user.get('company_id', 'N/A'),
                'Password changed successfully',
                ip_address=request.remote_addr
            )
            
            # Revoke all sessions and tokens for security
            if hasattr(current_app, 'session_manager'):
                current_app.session_manager.end_all_user_sessions(user.get('payroll_id'))
            
            return True, None
            
        except Exception as e:
            logger.error(f"Password change error: {str(e)}")
            return False, str(e)
    
    def reset_password(self, token: str, new_password: str) -> Tuple[bool, Optional[str]]:
        """
        Reset a user's password using a reset token.
        
        Args:
            token: Password reset token
            new_password: User's new password
            
        Returns:
            Tuple[bool, Optional[str]]: (success, error_message)
        """
        try:
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Verify token
            reset_info = user_repo.verify_password_reset_token(token)
            
            if not reset_info:
                return False, "Invalid or expired reset token"
            
            user_id = reset_info.get('user_id')
            
            # Validate new password
            if len(new_password) < 8:
                return False, "New password must be at least 8 characters long"
            
            # Hash new password
            hashed_password = hash_password(new_password)
            
            # Update password
            success = user_repo.update_password(user_id, hashed_password)
            
            if not success:
                return False, "Failed to update password"
            
            # Clear reset token
            user_repo.clear_password_reset_token(token)
            
            # Get user for logging
            user = user_repo.find_by_id(user_id)
            
            # Log password reset
            AuditLogger.log_event(
                'password_reset',
                user.get('payroll_id', 'unknown'),
                user.get('company_id', 'N/A'),
                'Password reset successfully',
                ip_address=request.remote_addr
            )
            
            # Revoke all sessions and tokens for security
            if hasattr(current_app, 'session_manager'):
                current_app.session_manager.end_all_user_sessions(user.get('payroll_id'))
            
            return True, None
            
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            return False, str(e)
    
    def create_password_reset_token(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Create a password reset token for a user.
        
        Args:
            email: User's email address
            
        Returns:
            Tuple[bool, Optional[str]]: (success, error_message)
        """
        try:
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Find user by email
            user = user_repo.find_by_email(email)
            
            if not user:
                # Don't reveal that user doesn't exist
                return True, None
            
            # Generate reset token
            token = user_repo.create_password_reset_token(str(user.get('_id')))
            
            if not token:
                return False, "Failed to create reset token"
            
            # TODO: Send reset email (would be handled by notification service)
            
            # Log token creation
            AuditLogger.log_event(
                'password_reset_requested',
                user.get('payroll_id', 'unknown'),
                user.get('company_id', 'N/A'),
                'Password reset requested',
                ip_address=request.remote_addr
            )
            
            return True, None
            
        except Exception as e:
            logger.error(f"Password reset token creation error: {str(e)}")
            return False, str(e)
    
    def setup_mfa(self, user_id: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Set up MFA for a user.
        
        Args:
            user_id: User's MongoDB ID
            
        Returns:
            Tuple[bool, Optional[Dict], Optional[str]]: (success, setup_data, error_message)
        """
        try:
            # Check if MFA manager is available
            if not hasattr(current_app, 'mfa_manager'):
                return False, None, "MFA not configured"
            
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Find user
            user = user_repo.find_by_id(user_id)
            
            if not user:
                return False, None, "User not found"
            
            # Check if MFA is already set up
            mfa_status = current_app.mfa_manager.get_mfa_status(user.get('payroll_id'))
            
            if mfa_status.get('is_enabled'):
                return False, None, "MFA is already enabled for this account"
            
            # Set up TOTP MFA
            secret, qr_code, recovery_codes = current_app.mfa_manager.setup_totp_mfa(
                user_id,
                user.get('payroll_id')
            )
            
            # Return setup data (without recovery codes until verified)
            setup_data = {
                'secret': secret,
                'qr_code_available': True
            }
            
            return True, setup_data, None
            
        except Exception as e:
            logger.error(f"MFA setup error: {str(e)}")
            return False, None, str(e)
    
    def verify_mfa_setup(self, user_id: str, code: str) -> Tuple[bool, Optional[List[str]], Optional[str]]:
        """
        Verify MFA setup with a TOTP code.
        
        Args:
            user_id: User's MongoDB ID
            code: TOTP code to verify
            
        Returns:
            Tuple[bool, Optional[List[str]], Optional[str]]: (success, recovery_codes, error_message)
        """
        try:
            # Check if MFA manager is available
            if not hasattr(current_app, 'mfa_manager'):
                return False, None, "MFA not configured"
            
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Find user
            user = user_repo.find_by_id(user_id)
            
            if not user:
                return False, None, "User not found"
            
            # Get MFA data
            mfa_data = current_app.mongo.db.mfa.find_one({"payroll_id": user.get('payroll_id')})
            
            if not mfa_data:
                return False, None, "No MFA setup in progress"
            
            # Verify code
            secret = mfa_data.get('totp_secret')
            if not current_app.mfa_manager._verify_totp(secret, code):
                return False, None, "Invalid verification code"
            
            # Update MFA status to active
            current_app.mongo.db.mfa.update_one(
                {"payroll_id": user.get('payroll_id')},
                {"$set": {"status": "active"}}
            )
            
            # Get recovery codes
            recovery_codes = mfa_data.get('recovery_codes', [])
            
            # Log MFA activation
            AuditLogger.log_event(
                'mfa_activated',
                user.get('payroll_id'),
                user.get('company_id', 'N/A'),
                'MFA activated successfully',
                ip_address=request.remote_addr
            )
            
            return True, recovery_codes, None
            
        except Exception as e:
            logger.error(f"MFA setup verification error: {str(e)}")
            return False, None, str(e)
    
    def disable_mfa(self, user_id: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Disable MFA for a user.
        
        Args:
            user_id: User's MongoDB ID
            password: User's password for verification
            
        Returns:
            Tuple[bool, Optional[str]]: (success, error_message)
        """
        try:
            # Check if MFA manager is available
            if not hasattr(current_app, 'mfa_manager'):
                return False, "MFA not configured"
            
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Find user
            user = user_repo.find_by_id(user_id)
            
            if not user:
                return False, "User not found"
            
            # Verify password
            if not check_password(user.get('password', ''), password):
                return False, "Invalid password"
            
            # Disable MFA
            success = current_app.mfa_manager.disable_mfa(user.get('payroll_id'))
            
            if not success:
                return False, "Failed to disable MFA"
            
            # Log MFA deactivation
            AuditLogger.log_event(
                'mfa_deactivated',
                user.get('payroll_id'),
                user.get('company_id', 'N/A'),
                'MFA deactivated',
                ip_address=request.remote_addr
            )
            
            return True, None
            
        except Exception as e:
            logger.error(f"MFA disable error: {str(e)}")
            return False, str(e)
    
    def get_mfa_status(self, user_id: str) -> Dict[str, Any]:
        """
        Get MFA status for a user.
        
        Args:
            user_id: User's MongoDB ID
            
        Returns:
            Dict: MFA status information
        """
        try:
            # Check if MFA manager is available
            if not hasattr(current_app, 'mfa_manager'):
                return {"is_enabled": False, "error": "MFA not configured"}
            
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Find user
            user = user_repo.find_by_id(user_id)
            
            if not user:
                return {"is_enabled": False, "error": "User not found"}
            
            # Get MFA status
            return current_app.mfa_manager.get_mfa_status(user.get('payroll_id'))
            
        except Exception as e:
            logger.error(f"Error getting MFA status: {str(e)}")
            return {"is_enabled": False, "error": str(e)}
    
    def refresh_session(self, refresh_token: str) -> Tuple[bool, Optional[Dict], Optional[str], Optional[str]]:
        """
        Refresh a session using a refresh token.
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            Tuple[bool, Optional[Dict], Optional[str], Optional[str]]: 
                (success, user_data, new_session_id, new_refresh_token)
        """
        try:
            # Check if session manager is available
            if not hasattr(current_app, 'session_manager'):
                return False, None, None, "Session management not available"
            
            # Refresh session
            success, session_id, new_refresh_token = current_app.session_manager.refresh_session(refresh_token)
            
            if not success:
                return False, None, None, "Invalid or expired refresh token"
            
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Get user from session
            user_data = current_app.session_manager.get_user_data()
            
            if not user_data:
                return False, None, None, "Session data not found"
            
            # Get full user data
            user = user_repo.find_by_payroll_id(user_data.get('payroll_id'))
            
            if not user:
                return False, None, None, "User not found"
            
            return True, user, session_id, new_refresh_token
            
        except Exception as e:
            logger.error(f"Session refresh error: {str(e)}")
            return False, None, None, str(e)
    
    def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User's MongoDB ID
            
        Returns:
            List[Dict]: List of active session data
        """
        try:
            # Check if session manager is available
            if not hasattr(current_app, 'session_manager'):
                return []
            
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Find user
            user = user_repo.find_by_id(user_id)
            
            if not user:
                return []
            
            # Get active sessions
            return current_app.session_manager.get_active_sessions(user.get('payroll_id'))
            
        except Exception as e:
            logger.error(f"Error getting active sessions: {str(e)}")
            return []
    
    def terminate_session(self, user_id: str, session_id: str) -> bool:
        """
        Terminate a specific session for a user.
        
        Args:
            user_id: User's MongoDB ID
            session_id: Session ID to terminate
            
        Returns:
            bool: True if session was terminated, False otherwise
        """
        try:
            # Check if session manager is available
            if not hasattr(current_app, 'session_manager'):
                return False
            
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Find user
            user = user_repo.find_by_id(user_id)
            
            if not user:
                return False
            
            # Check if session belongs to user
            db = current_app.mongo.db
            session_doc = db.active_sessions.find_one({
                'session_id': session_id,
                'user_id': user.get('payroll_id')
            })
            
            if not session_doc:
                return False
            
            # Remove session
            current_app.session_manager._remove_session(session_id)
            
            # Remove from Redis
            if hasattr(current_app.session_manager, 'redis_client') and current_app.session_manager.redis_client:
                current_app.session_manager.redis_client.delete(f"session:{session_id}")
            
            # Log session termination
            AuditLogger.log_event(
                'session_terminated',
                user.get('payroll_id'),
                user.get('company_id', 'N/A'),
                f'Session {session_id} terminated',
                ip_address=request.remote_addr
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Session termination error: {str(e)}")
            return False
    
    def terminate_all_sessions(self, user_id: str) -> bool:
        """
        Terminate all sessions for a user.
        
        Args:
            user_id: User's MongoDB ID
            
        Returns:
            bool: True if sessions were terminated, False otherwise
        """
        try:
            # Check if session manager is available
            if not hasattr(current_app, 'session_manager'):
                return False
            
            # Get user repository
            user_repo = self._get_user_repository()
            
            # Find user
            user = user_repo.find_by_id(user_id)
            
            if not user:
                return False
            
            # End all sessions
            return current_app.session_manager.end_all_user_sessions(user.get('payroll_id'))
            
        except Exception as e:
            logger.error(f"Error terminating all sessions: {str(e)}")
            return False
    
    def _is_mfa_required(self, user: Dict) -> bool:
        """
        Check if MFA is required for a user.
        
        Args:
            user: User document
            
        Returns:
            bool: True if MFA is required, False otherwise
        """
        # Check if MFA manager is available
        if not hasattr(current_app, 'mfa_manager'):
            return False
        
        # Get MFA status
        mfa_status = current_app.mfa_manager.get_mfa_status(user.get('payroll_id'))
        
        return mfa_status.get('is_enabled', False)
    
    def _get_user_repository(self) -> UserRepository:
        """
        Get or create a user repository.
        
        Returns:
            UserRepository: User repository instance
        """
        if self.user_repository:
            return self.user_repository
        
        # Try to get from app context
        if hasattr(g, 'user_repository'):
            return g.user_repository
        
        # Create new repository
        from repositories.user_repository import UserRepository
        db = current_app.mongo.db
        
        self.user_repository = UserRepository(db)
        return self.user_repository


# Initialize function
def init_auth_service(app):
    """
    Initialize the Authentication Service with the application context.
    
    Args:
        app: Flask application instance
        
    Returns:
        AuthenticationService: Initialized authentication service instance
    """
    # Get user repository
    if hasattr(app, 'user_repository'):
        user_repository = app.user_repository
    else:
        from repositories.user_repository import UserRepository
        user_repository = UserRepository(app.mongo.db)
    
    # Create service
    auth_service = AuthenticationService(user_repository)
    
    # Register with app
    app.auth_service = auth_service
    
    return auth_service
