# ------------------------------------------------------------
# utils/auth/session_manager.py
# ------------------------------------------------------------
"""
Enhanced session management with refresh tokens, inactivity timeouts, and activity tracking.
"""
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import logging
import secrets
import json
from flask import session, request, current_app, g
from pymongo import MongoClient, ASCENDING, DESCENDING
from werkzeug.local import LocalProxy
from redis import Redis
import time

from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class SessionExpiredError(Exception):
    """Custom exception for expired sessions."""
    pass

class SessionInvalidError(Exception):
    """Custom exception for invalid sessions."""
    pass

class SessionManager:
    """
    Enhanced session manager with refresh tokens and timeout capabilities.
    
    Features:
    - Configurable session lifetime and inactivity timeout
    - Refresh token mechanism to extend sessions securely
    - Session state storage in Redis for quick validation
    - Activity tracking for security auditing
    - Inactivity detection and automatic session expiration
    - Forceful session termination across devices
    """
    
    def __init__(self, app=None, redis_client=None):
        """
        Initialize the Session Manager.
        
        Args:
            app: Flask application instance
            redis_client: Optional Redis client for session state storage
        """
        self.app = app
        self.redis_client = redis_client
        self.mongo_db = None
        
        # Default session configuration
        self.session_lifetime = timedelta(hours=8)  # Total session lifetime
        self.activity_timeout = timedelta(minutes=30)  # Inactivity timeout
        self.refresh_window = timedelta(minutes=5)  # Window before expiry to offer refresh
        self.refresh_token_lifetime = timedelta(days=7)  # Refresh token lifetime
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """
        Initialize with Flask app instance.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Apply configuration from app config
        self.session_lifetime = app.config.get('SESSION_LIFETIME', timedelta(hours=8))
        self.activity_timeout = app.config.get('SESSION_ACTIVITY_TIMEOUT', timedelta(minutes=30))
        self.refresh_window = app.config.get('SESSION_REFRESH_WINDOW', timedelta(minutes=5))
        self.refresh_token_lifetime = app.config.get('REFRESH_TOKEN_LIFETIME', timedelta(days=7))
        
        # Initialize Redis client if not provided
        if self.redis_client is None and app.config.get('REDIS_URL'):
            self.redis_client = Redis.from_url(app.config.get('REDIS_URL'))
        
        # Set secure session configuration
        app.config.setdefault('PERMANENT_SESSION_LIFETIME', self.session_lifetime)
        app.config.setdefault('SESSION_COOKIE_SECURE', True)
        app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
        app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
        
        # Create indexes for session collections
        @app.before_first_request
        def setup_session_collection():
            db = self._get_db()
            
            # Create indexes for refresh tokens collection
            db.refresh_tokens.create_index([('user_id', ASCENDING), ('token', ASCENDING)], unique=True)
            db.refresh_tokens.create_index([('expires_at', ASCENDING)])
            
            # Create indexes for session tracking collection
            db.active_sessions.create_index([('session_id', ASCENDING)], unique=True)
            db.active_sessions.create_index([('user_id', ASCENDING)])
            db.active_sessions.create_index([('last_activity', ASCENDING)])
        
        # Add before_request hook to check session validity
        @app.before_request
        def check_session_validity():
            # Skip for auth routes
            if request.endpoint and (
                request.endpoint.startswith('auth.') or 
                request.endpoint.startswith('static') or
                request.endpoint == 'auth'
            ):
                return
            
            # Check if session exists
            if 'user' not in session:
                return
            
            try:
                # Check if session has expired due to inactivity
                if not self.is_session_active():
                    self.end_session(reason='inactivity')
                    raise SessionExpiredError("Session expired due to inactivity")
                
                # Update last activity timestamp
                self.update_activity()
                
            except (SessionExpiredError, SessionInvalidError):
                # Clear session
                session.clear()
                
                # If it's an API request, return 401
                if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    from flask import jsonify
                    return jsonify({'success': False, 'message': 'Session expired'}), 401
                
                # For regular requests, redirect to login
                from flask import redirect, url_for
                return redirect(url_for('auth.login'))
            
            except Exception as e:
                logger.error(f"Error checking session validity: {str(e)}")
        
        # Register with app context
        app.session_manager = self
    
    def create_session(self, user_data: Dict[str, Any]) -> Tuple[str, str]:
        """
        Create a new user session with refresh token.
        
        Args:
            user_data: Dictionary containing user information
            
        Returns:
            Tuple[str, str]: (session_id, refresh_token)
        """
        try:
            # Generate session ID
            session_id = secrets.token_urlsafe(32)
            
            # Generate refresh token
            refresh_token = secrets.token_urlsafe(64)
            
            # Set core session data
            session['user'] = {
                'payroll_id': user_data['payroll_id'],
                'email_work': user_data.get('work_email', ''),
                'role': user_data.get('role', ''),
                'business_id': user_data.get('company_id', ''),
                'venue_id': user_data.get('venue_id', ''),
                'work_area_id': user_data.get('work_area_id', '')
            }
            
            # Set session metadata
            session['session_id'] = session_id
            session['created_at'] = datetime.utcnow().isoformat()
            session['last_active'] = datetime.utcnow().isoformat()
            session['expires_at'] = (datetime.utcnow() + self.session_lifetime).isoformat()
            
            # Store refresh token in database
            self._store_refresh_token(
                user_data['payroll_id'],
                str(user_data.get('_id', '')),
                refresh_token,
                datetime.utcnow() + self.refresh_token_lifetime
            )
            
            # Store session in database for tracking
            self._store_session(
                session_id,
                user_data['payroll_id'],
                str(user_data.get('_id', '')),
                request.remote_addr,
                request.user_agent.string
            )
            
            # Store session in Redis for quick lookups
            if self.redis_client:
                session_data = {
                    'user_id': user_data['payroll_id'],
                    'created_at': datetime.utcnow().timestamp(),
                    'last_active': datetime.utcnow().timestamp(),
                    'expires_at': (datetime.utcnow() + self.session_lifetime).timestamp()
                }
                self.redis_client.setex(
                    f"session:{session_id}",
                    int(self.session_lifetime.total_seconds()),
                    json.dumps(session_data)
                )
            
            # Log session creation
            AuditLogger.log_event(
                'session_created',
                user_data['payroll_id'],
                user_data.get('company_id', 'N/A'),
                'User session created',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            return session_id, refresh_token
            
        except Exception as e:
            logger.error(f"Error creating session: {str(e)}")
            raise
    
    def refresh_session(self, refresh_token: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Refresh an expired session using a refresh token.
        
        Args:
            refresh_token: Refresh token to use
            
        Returns:
            Tuple[bool, Optional[str], Optional[str]]: (success, new_session_id, new_refresh_token)
        """
        try:
            # Find refresh token in database
            db = self._get_db()
            token_doc = db.refresh_tokens.find_one({'token': refresh_token})
            
            if not token_doc:
                logger.warning(f"Invalid refresh token used: {refresh_token[:10]}...")
                return False, None, None
            
            # Check if token has expired
            expires_at = token_doc.get('expires_at')
            if expires_at and expires_at < datetime.utcnow():
                logger.warning(f"Expired refresh token used: {refresh_token[:10]}...")
                return False, None, None
            
            # Get user data
            user_id = token_doc.get('user_id')
            user = db.business_users.find_one({'payroll_id': user_id})
            
            if not user:
                logger.warning(f"User not found for refresh token: {refresh_token[:10]}...")
                return False, None, None
            
            # Invalidate old refresh token
            db.refresh_tokens.delete_one({'token': refresh_token})
            
            # Create new session
            session_id, new_refresh_token = self.create_session(user)
            
            # Log session refresh
            AuditLogger.log_event(
                'session_refreshed',
                user_id,
                user.get('company_id', 'N/A'),
                'Session refreshed with token',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            return True, session_id, new_refresh_token
            
        except Exception as e:
            logger.error(f"Error refreshing session: {str(e)}")
            return False, None, None
    
    def end_session(self, reason: str = 'user_logout') -> bool:
        """
        End the current user session.
        
        Args:
            reason: Reason for ending the session
            
        Returns:
            bool: True if session ended successfully, False otherwise
        """
        try:
            # Get session data for logging
            session_id = session.get('session_id')
            user_data = session.get('user', {})
            
            # Remove session from database
            if session_id:
                self._remove_session(session_id)
                
                # Remove from Redis
                if self.redis_client:
                    self.redis_client.delete(f"session:{session_id}")
            
            # Clear session
            session.clear()
            
            # Log session end
            if user_data:
                AuditLogger.log_event(
                    'session_ended',
                    user_data.get('payroll_id', 'unknown'),
                    user_data.get('business_id', 'N/A'),
                    f'Session ended: {reason}',
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string
                )
            
            return True
            
        except Exception as e:
            logger.error(f"Error ending session: {str(e)}")
            return False
    
    def end_all_user_sessions(self, payroll_id: str) -> bool:
        """
        End all sessions for a specific user.
        Useful for forced logout scenarios or security breaches.
        
        Args:
            payroll_id: User's payroll ID
            
        Returns:
            bool: True if sessions were ended successfully, False otherwise
        """
        try:
            # Get database connection
            db = self._get_db()
            
            # Find all active sessions for user
            active_sessions = list(db.active_sessions.find({'user_id': payroll_id}))
            
            # Remove all sessions from database
            db.active_sessions.delete_many({'user_id': payroll_id})
            
            # Remove all refresh tokens for user
            db.refresh_tokens.delete_many({'user_id': payroll_id})
            
            # Remove from Redis
            if self.redis_client:
                for session_doc in active_sessions:
                    session_id = session_doc.get('session_id')
                    if session_id:
                        self.redis_client.delete(f"session:{session_id}")
            
            # Log session termination
            AuditLogger.log_event(
                'all_sessions_terminated',
                payroll_id,
                'N/A',
                f'All sessions terminated for user: {payroll_id}',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            # End current session if it belongs to the user
            if session.get('user', {}).get('payroll_id') == payroll_id:
                session.clear()
            
            return True
            
        except Exception as e:
            logger.error(f"Error ending all user sessions: {str(e)}")
            return False
    
    def is_session_active(self) -> bool:
        """
        Check if the current session is active and valid.
        
        Returns:
            bool: True if session is active, False otherwise
        """
        try:
            # Check if session exists
            if 'user' not in session or 'session_id' not in session:
                return False
            
            # Get session ID
            session_id = session.get('session_id')
            
            # Try Redis first for performance
            if self.redis_client:
                session_data = self.redis_client.get(f"session:{session_id}")
                if session_data:
                    # Session exists in Redis
                    try:
                        data = json.loads(session_data)
                        last_active = datetime.fromtimestamp(data.get('last_active', 0))
                        expires_at = datetime.fromtimestamp(data.get('expires_at', 0))
                        
                        # Check if session has expired
                        if datetime.utcnow() > expires_at:
                            return False
                        
                        # Check inactivity timeout
                        if datetime.utcnow() - last_active > self.activity_timeout:
                            return False
                        
                        return True
                    except (json.JSONDecodeError, TypeError, ValueError):
                        # Fall back to database check if Redis data is corrupt
                        pass
            
            # Check MongoDB
            db = self._get_db()
            session_doc = db.active_sessions.find_one({'session_id': session_id})
            
            if not session_doc:
                return False
            
            # Get timestamps
            last_activity = session_doc.get('last_activity', datetime.min)
            created_at = session_doc.get('created_at', datetime.min)
            
            # Check if session has expired due to inactivity
            if datetime.utcnow() - last_activity > self.activity_timeout:
                return False
            
            # Check if session has exceeded its maximum lifetime
            if datetime.utcnow() - created_at > self.session_lifetime:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking session activity: {str(e)}")
            return False
    
    def update_activity(self) -> bool:
        """
        Update last activity timestamp for the current session.
        
        Returns:
            bool: True if update successful, False otherwise
        """
        try:
            # Check if session exists
            if 'user' not in session or 'session_id' not in session:
                return False
            
            # Get session ID
            session_id = session.get('session_id')
            
            # Update timestamp in session
            session['last_active'] = datetime.utcnow().isoformat()
            
            # Update in Redis
            if self.redis_client:
                session_data_raw = self.redis_client.get(f"session:{session_id}")
                if session_data_raw:
                    try:
                        session_data = json.loads(session_data_raw)
                        session_data['last_active'] = datetime.utcnow().timestamp()
                        
                        # Calculate TTL in seconds
                        expires_at = datetime.fromtimestamp(session_data.get('expires_at', 0))
                        ttl = max(1, int((expires_at - datetime.utcnow()).total_seconds()))
                        
                        self.redis_client.setex(
                            f"session:{session_id}",
                            ttl,
                            json.dumps(session_data)
                        )
                    except (json.JSONDecodeError, TypeError, ValueError):
                        pass
            
            # Update in database
            db = self._get_db()
            db.active_sessions.update_one(
                {'session_id': session_id},
                {'$set': {'last_activity': datetime.utcnow()}}
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating session activity: {str(e)}")
            return False
    
    def get_user_data(self) -> Optional[Dict[str, Any]]:
        """
        Get current user data from session.
        
        Returns:
            Dict: User data dictionary or None if no session exists
        """
        # Validate session before returning data
        if not self.is_session_active():
            return None
        
        return session.get('user')
    
    def get_active_sessions(self, payroll_id: str) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user.
        
        Args:
            payroll_id: User's payroll ID
            
        Returns:
            List[Dict]: List of active session data
        """
        try:
            db = self._get_db()
            active_sessions = list(db.active_sessions.find(
                {'user_id': payroll_id},
                {'_id': 0, 'session_id': 1, 'created_at': 1, 'last_activity': 1, 
                 'ip_address': 1, 'user_agent': 1, 'device_info': 1}
            ))
            
            # Format timestamps for response
            for session in active_sessions:
                if isinstance(session.get('created_at'), datetime):
                    session['created_at'] = session['created_at'].isoformat()
                if isinstance(session.get('last_activity'), datetime):
                    session['last_activity'] = session['last_activity'].isoformat()
            
            return active_sessions
            
        except Exception as e:
            logger.error(f"Error getting active sessions: {str(e)}")
            return []
    
    def revoke_refresh_token(self, refresh_token: str) -> bool:
        """
        Revoke a refresh token.
        
        Args:
            refresh_token: Refresh token to revoke
            
        Returns:
            bool: True if token was revoked, False otherwise
        """
        try:
            db = self._get_db()
            result = db.refresh_tokens.delete_one({'token': refresh_token})
            
            return result.deleted_count > 0
            
        except Exception as e:
            logger.error(f"Error revoking refresh token: {str(e)}")
            return False
    
    def needs_refresh(self) -> bool:
        """
        Check if the current session needs to be refreshed.
        
        Returns:
            bool: True if session is approaching expiry, False otherwise
        """
        try:
            # Check if session exists
            if 'user' not in session or 'expires_at' not in session:
                return False
            
            # Get expiry timestamp
            expires_at = datetime.fromisoformat(session.get('expires_at'))
            
            # Check if within refresh window
            return datetime.utcnow() + self.refresh_window > expires_at
            
        except Exception as e:
            logger.error(f"Error checking if session needs refresh: {str(e)}")
            return False
    
    def is_authenticated(self) -> bool:
        """
        Check if a user is currently authenticated with a valid session.
        
        Returns:
            bool: True if authenticated, False otherwise
        """
        return self.is_session_active() and 'user' in session
    
    def _store_refresh_token(self, user_id: str, user_obj_id: str, token: str, expires_at: datetime) -> bool:
        """
        Store a refresh token in the database.
        
        Args:
            user_id: User's payroll ID
            user_obj_id: User's MongoDB object ID
            token: Refresh token
            expires_at: Token expiry timestamp
            
        Returns:
            bool: True if token was stored, False otherwise
        """
        try:
            db = self._get_db()
            
            # Create token document
            token_doc = {
                'user_id': user_id,
                'user_obj_id': user_obj_id,
                'token': token,
                'created_at': datetime.utcnow(),
                'expires_at': expires_at,
                'client_ip': request.remote_addr,
                'user_agent': request.user_agent.string
            }
            
            # Store in database
            result = db.refresh_tokens.insert_one(token_doc)
            
            return bool(result.inserted_id)
            
        except Exception as e:
            logger.error(f"Error storing refresh token: {str(e)}")
            return False
    
    def _store_session(self, session_id: str, user_id: str, user_obj_id: str, 
                       ip_address: str, user_agent: str) -> bool:
        """
        Store session information in the database.
        
        Args:
            session_id: Session ID
            user_id: User's payroll ID
            user_obj_id: User's MongoDB object ID
            ip_address: Client IP address
            user_agent: Client user agent string
            
        Returns:
            bool: True if session was stored, False otherwise
        """
        try:
            db = self._get_db()
            
            # Parse user agent for device info
            device_info = self._parse_user_agent(user_agent)
            
            # Create session document
            session_doc = {
                'session_id': session_id,
                'user_id': user_id,
                'user_obj_id': user_obj_id,
                'created_at': datetime.utcnow(),
                'last_activity': datetime.utcnow(),
                'expires_at': datetime.utcnow() + self.session_lifetime,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'device_info': device_info
            }
            
            # Store in database
            result = db.active_sessions.insert_one(session_doc)
            
            return bool(result.inserted_id)
            
        except Exception as e:
            logger.error(f"Error storing session: {str(e)}")
            return False
    
    def _remove_session(self, session_id: str) -> bool:
        """
        Remove a session from the database.
        
        Args:
            session_id: Session ID to remove
            
        Returns:
            bool: True if session was removed, False otherwise
        """
        try:
            db = self._get_db()
            result = db.active_sessions.delete_one({'session_id': session_id})
            
            return result.deleted_count > 0
            
        except Exception as e:
            logger.error(f"Error removing session: {str(e)}")
            return False
    
    def _parse_user_agent(self, user_agent_string: str) -> Dict[str, str]:
        """
        Parse user agent string for device information.
        
        Args:
            user_agent_string: User agent string
            
        Returns:
            Dict: Device information
        """
        device_info = {
            'browser': 'Unknown',
            'browser_version': 'Unknown',
            'os': 'Unknown',
            'os_version': 'Unknown',
            'device': 'Unknown',
            'is_mobile': False
        }
        
        try:
            user_agent = request.user_agent
            
            # Browser information
            if user_agent.browser:
                device_info['browser'] = user_agent.browser
                device_info['browser_version'] = user_agent.version
            
            # Platform information
            if user_agent.platform:
                device_info['os'] = user_agent.platform
            
            # Mobile detection
            device_info['is_mobile'] = user_agent.platform in ['android', 'iphone', 'ipad']
            
            # Attempt to extract device information
            if 'iPhone' in user_agent_string:
                device_info['device'] = 'iPhone'
            elif 'iPad' in user_agent_string:
                device_info['device'] = 'iPad'
            elif 'Android' in user_agent_string:
                device_info['device'] = 'Android'
            elif 'Windows' in user_agent_string:
                device_info['device'] = 'Windows'
            elif 'Macintosh' in user_agent_string:
                device_info['device'] = 'Mac'
            elif 'Linux' in user_agent_string:
                device_info['device'] = 'Linux'
            
            return device_info
            
        except Exception as e:
            logger.error(f"Error parsing user agent: {str(e)}")
            return device_info
    
    def _get_db(self):
        """Get MongoDB database connection."""
        if self.mongo_db:
            return self.mongo_db
            
        if hasattr(current_app, 'mongo'):
            self.mongo_db = current_app.mongo.db
            return self.mongo_db
            
        elif 'mongo' in g:
            self.mongo_db = g.mongo.db
            return self.mongo_db
            
        else:
            # Create a new connection
            client = MongoClient(current_app.config['MONGO_URI'])
            self.mongo_db = client[current_app.config['MONGO_DBNAME']]
            return self.mongo_db
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions and refresh tokens.
        
        Returns:
            int: Number of expired items removed
        """
        try:
            db = self._get_db()
            
            # Delete expired sessions
            sessions_result = db.active_sessions.delete_many({
                '$or': [
                    {'last_activity': {'$lt': datetime.utcnow() - self.activity_timeout}},
                    {'created_at': {'$lt': datetime.utcnow() - self.session_lifetime}}
                ]
            })
            
            # Delete expired refresh tokens
            tokens_result = db.refresh_tokens.delete_many({
                'expires_at': {'$lt': datetime.utcnow()}
            })
            
            return sessions_result.deleted_count + tokens_result.deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up expired sessions: {str(e)}")
            return 0


# Initialize function
def init_session_manager(app, redis_client=None):
    """
    Initialize the Session Manager with the application context.
    
    Args:
        app: Flask application instance
        redis_client: Optional Redis client for session state storage
        
    Returns:
        SessionManager: Initialized session manager instance
    """
    session_manager = SessionManager(app, redis_client)
    app.session_manager = session_manager
    return session_manager


# Flask extension for session management
class FlaskSessionManager:
    """Flask extension for session management."""
    
    def __init__(self, app=None, redis_client=None):
        self.session_manager = None
        if app is not None:
            self.init_app(app, redis_client)
    
    def init_app(self, app, redis_client=None):
        """
        Initialize the extension with the given application.
        
        Args:
            app: Flask application instance
            redis_client: Optional Redis client for session state storage
        """
        self.session_manager = SessionManager(app, redis_client)
        app.session_manager = self.session_manager
        
        # Register teardown function
        @app.teardown_appcontext
        def teardown_session_manager(exception=None):
            pass  # No cleanup needed for now
        
        # Add session_manager to app.extensions
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['session_manager'] = self.session_manager


# Define a proxy for accessing the current session manager
def _get_session_manager():
    """Get the current session manager."""
    if hasattr(current_app, 'session_manager'):
        return current_app.session_manager
    
    if hasattr(current_app, 'extensions') and 'session_manager' in current_app.extensions:
        return current_app.extensions['session_manager']
    
    raise RuntimeError('Session manager not initialized with app')

current_session_manager = LocalProxy(_get_session_manager)
