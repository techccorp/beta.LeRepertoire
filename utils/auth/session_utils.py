# ------------------------------------------------------------
# utils/auth/session_utils.py - Updated Import
# ------------------------------------------------------------
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import logging
from flask import session, current_app
from utils.logging import AuditLogger  # New correct path

logger = logging.getLogger(__name__)

class SessionManager:
    """
    Manages user sessions with enhanced security and Google OAuth support.
    
    Features:
    - Secure session handling
    - Google OAuth integration
    - Session expiration management
    - Activity tracking
    - Audit logging
    """

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize with Flask app instance."""
        self.app = app
        # Set secure session configuration
        app.config.setdefault('PERMANENT_SESSION_LIFETIME', timedelta(hours=8))
        app.config.setdefault('SESSION_COOKIE_SECURE', True)
        app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
        app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')

    def create_session(self, user_data: Dict[str, Any], google_credentials: Optional[Dict] = None) -> None:
        """
        Create a new user session with optional Google credentials.
        
        Args:
            user_data: Dictionary containing user information.
                       Expected keys: 'payroll_id', 'work_email', 'role', 'company_id',
                       'venue_id', 'work_area_id'
            google_credentials: Optional dictionary with Google OAuth credentials.
        """
        try:
            # Set core session data using top-level keys from the user document
            session['user'] = {
                'payroll_id': user_data['payroll_id'],
                'email_work': user_data['work_email'],
                'role': user_data['role'],
                'business_id': user_data['company_id'],
                'venue_id': user_data['venue_id'],
                'work_area_id': user_data['work_area_id']
            }
            
            # Set session timestamps
            session['created_at'] = datetime.utcnow().isoformat()
            session['last_active'] = datetime.utcnow().isoformat()
            
            # Set Google credentials if provided
            if google_credentials:
                session['google_credentials'] = google_credentials
                session['google_last_refresh'] = datetime.utcnow().isoformat()
            
            # Log session creation
            AuditLogger.log_event(
                'session_created',
                user_data['payroll_id'],
                user_data['company_id'],
                'User session created successfully'
            )
            
        except Exception as e:
            logger.error(f"Error creating session: {str(e)}")
            raise

    def end_session(self) -> None:
        """
        End the current user session and perform cleanup.
        """
        try:
            if 'user' in session:
                # Log session end
                AuditLogger.log_event(
                    'session_ended',
                    session['user'].get('payroll_id'),
                    session['user'].get('business_id'),
                    'User session ended'
                )
            
            # Clear session
            session.clear()
            
        except Exception as e:
            logger.error(f"Error ending session: {str(e)}")
            raise

    def refresh_session(self) -> None:
        """
        Refresh session timestamp and validate session data.
        """
        try:
            if 'user' in session:
                session['last_active'] = datetime.utcnow().isoformat()
                
                # Check session age
                created_at = datetime.fromisoformat(session['created_at'])
                if datetime.utcnow() - created_at > current_app.config['PERMANENT_SESSION_LIFETIME']:
                    self.end_session()
                    raise SessionExpiredError("Session has expired")
                    
        except Exception as e:
            logger.error(f"Error refreshing session: {str(e)}")
            raise

    def get_user_data(self) -> Optional[Dict[str, Any]]:
        """
        Get current user data from session.
        
        Returns:
            Dictionary containing user data or None if no session exists.
        """
        return session.get('user')

    def update_google_credentials(self, credentials: Dict[str, Any]) -> None:
        """
        Update Google OAuth credentials in session.
        
        Args:
            credentials: Dictionary containing Google OAuth credentials.
        """
        try:
            session['google_credentials'] = credentials
            session['google_last_refresh'] = datetime.utcnow().isoformat()
            
            AuditLogger.log_event(
                'google_credentials_updated',
                session['user'].get('payroll_id'),
                session['user'].get('business_id'),
                'Google credentials updated'
            )
            
        except Exception as e:
            logger.error(f"Error updating Google credentials: {str(e)}")
            raise

    def is_authenticated(self) -> bool:
        """
        Check if the current session is authenticated.
        
        Returns:
            True if authenticated, False otherwise.
        """
        return 'user' in session

    def get_session_age(self) -> Optional[timedelta]:
        """
        Get age of the current session.
        
        Returns:
            timedelta representing session age, or None if no session exists.
        """
        if 'created_at' in session:
            return datetime.utcnow() - datetime.fromisoformat(session['created_at'])
        return None

class SessionExpiredError(Exception):
    """Custom exception for expired sessions."""
    pass

# Add the missing standalone functions that are imported in __init__.py
def create_session(user_data: Dict[str, Any], google_credentials: Optional[Dict] = None) -> None:
    """
    Create a new user session (standalone function wrapper for SessionManager).
    
    Args:
        user_data: Dictionary containing user information
        google_credentials: Optional dictionary with Google OAuth credentials
    """
    manager = SessionManager(current_app)
    return manager.create_session(user_data, google_credentials)

def get_session() -> Optional[Dict[str, Any]]:
    """
    Get the entire current session data.
    
    Returns:
        Dictionary containing session data or None if no session exists
    """
    return session if session else None

def delete_session() -> None:
    """
    Delete the current session.
    """
    manager = SessionManager(current_app)
    return manager.end_session()

def refresh_session() -> None:
    """
    Refresh the current session timestamp.
    """
    manager = SessionManager(current_app)
    return manager.refresh_session()

def validate_session() -> bool:
    """
    Validate that the current session is active and authenticated.
    
    Returns:
        True if session is valid, False otherwise
    """
    if 'user' not in session:
        return False
    
    # Check session age
    try:
        created_at = datetime.fromisoformat(session['created_at'])
        if datetime.utcnow() - created_at > current_app.config['PERMANENT_SESSION_LIFETIME']:
            return False
        return True
    except (ValueError, KeyError):
        return False

def get_user_from_session() -> Optional[Dict[str, Any]]:
    """
    Get user data from the current session.
    
    Returns:
        Dictionary containing user data or None if no user in session
    """
    return session.get('user')

def set_user_in_session(user_data: Dict[str, Any]) -> None:
    """
    Set user data in the current session.
    
    Args:
        user_data: Dictionary containing user information
    """
    session['user'] = user_data
    session['last_active'] = datetime.utcnow().isoformat()
