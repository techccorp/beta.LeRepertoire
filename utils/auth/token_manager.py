# ------------------------------------------------------------
# utils/auth/token_manager.py
# ------------------------------------------------------------
"""
Token management system with revocation capabilities.
Provides secure token generation, verification, and revocation.
"""
from datetime import datetime, timedelta
import logging
from typing import Dict, Any, Optional, List
import jwt
from flask import current_app, g
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson.objectid import ObjectId
import time

logger = logging.getLogger(__name__)

class TokenManager:
    """
    Enhanced token management with revocation capabilities.
    
    Features:
    - Secure JWT token generation
    - Token verification with revocation check
    - Token revocation and blacklist management
    - Automatic cleanup of expired tokens
    """
    
    def __init__(self, app=None):
        """
        Initialize the Token Manager.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        self.token_cache = {}  # In-memory cache for revoked tokens
        self.last_cleanup = time.time()
        self.cleanup_interval = 3600  # 1 hour
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """
        Initialize with Flask app instance.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Create indexes for token collection
        @app.before_first_request
        def setup_token_collection():
            db = self._get_db()
            
            # Create indexes for efficient queries
            db.revoked_tokens.create_index([('jti', ASCENDING)], unique=True)
            db.revoked_tokens.create_index([('expires_at', ASCENDING)])
            
            # Cleanup on startup
            self._cleanup_expired_tokens()
    
    def generate_token(self, user_data: Dict[str, Any], expiry_hours: int = 8) -> str:
        """
        Generate a secure JWT token for authentication.
        
        Args:
            user_data: Dictionary containing user information
            expiry_hours: Token expiry time in hours
            
        Returns:
            str: Encoded JWT token
        """
        try:
            # Generate a unique token ID
            jti = str(ObjectId())
            
            # Create payload with user data and expiry
            expiry_time = datetime.utcnow() + timedelta(hours=expiry_hours)
            
            payload = {
                # Essential user identifiers
                'payroll_id': user_data['payroll_id'],
                'email': user_data.get('work_email', ''),
                
                # Role and permission context
                'role': user_data.get('role', ''),
                
                # Business context
                'business_id': user_data.get('company_id', ''),
                'venue_id': user_data.get('venue_id', ''),
                'work_area_id': user_data.get('work_area_id', ''),
                
                # Token metadata
                'jti': jti,
                'exp': expiry_time,
                'iat': datetime.utcnow()
            }
            
            # Encode and return token
            token = jwt.encode(
                payload,
                current_app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            
            # Store token metadata in session
            if g and hasattr(g, 'user'):
                g.user_token_jti = jti
            
            return token
            
        except Exception as e:
            logger.error(f"Token generation error: {str(e)}")
            raise
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode a JWT token, checking against revocation list.
        
        Args:
            token: JWT token to verify
            
        Returns:
            dict: Decoded token payload or None if invalid or revoked
        """
        try:
            # First, decode without verification to get the token ID (jti)
            # This is needed to check if the token is revoked before full verification
            unverified_payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )
            
            jti = unverified_payload.get('jti')
            
            # Check if token is revoked (fast in-memory check first)
            if jti and self._is_token_revoked(jti):
                logger.warning(f"Token with jti {jti} has been revoked")
                return None
            
            # Perform full token verification
            payload = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=['HS256']
            )
            
            # Periodic cleanup of expired tokens
            self._maybe_cleanup_expired_tokens()
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            return None
    
    def revoke_token(self, token: str = None, jti: str = None) -> bool:
        """
        Revoke a token by adding it to the revocation list.
        
        Args:
            token: JWT token to revoke (optional if jti is provided)
            jti: Token ID to revoke (optional if token is provided)
            
        Returns:
            bool: True if token was successfully revoked, False otherwise
        """
        try:
            # Get token ID (jti) from token if not provided
            if not jti and token:
                payload = jwt.decode(
                    token,
                    options={"verify_signature": False}
                )
                jti = payload.get('jti')
            
            # Get token from current user if neither token nor jti is provided
            if not jti and hasattr(g, 'user_token_jti'):
                jti = g.user_token_jti
            
            if not jti:
                logger.warning("Cannot revoke token: no token ID (jti) provided")
                return False
            
            # Calculate expiry time
            if token:
                payload = jwt.decode(
                    token,
                    options={"verify_signature": False}
                )
                expires_at = datetime.fromtimestamp(payload.get('exp', 0))
            else:
                # If we only have the jti, set expiry to 24 hours from now (conservative)
                expires_at = datetime.utcnow() + timedelta(hours=24)
            
            # Add to revocation list in database
            db = self._get_db()
            result = db.revoked_tokens.update_one(
                {'jti': jti},
                {
                    '$set': {
                        'jti': jti,
                        'revoked_at': datetime.utcnow(),
                        'expires_at': expires_at
                    }
                },
                upsert=True
            )
            
            # Add to in-memory cache
            self.token_cache[jti] = True
            
            logger.info(f"Token with jti {jti} has been revoked")
            return True
            
        except Exception as e:
            logger.error(f"Token revocation error: {str(e)}")
            return False
    
    def revoke_user_tokens(self, payroll_id: str) -> bool:
        """
        Revoke all tokens for a specific user.
        Useful for forced logout scenarios or security breaches.
        
        Args:
            payroll_id: User's payroll ID
            
        Returns:
            bool: True if tokens were successfully revoked, False otherwise
        """
        try:
            # Find all active tokens for the user
            db = self._get_db()
            active_tokens = db.active_tokens.find({'payroll_id': payroll_id})
            
            # Revoke each token
            for token_doc in active_tokens:
                self.revoke_token(jti=token_doc.get('jti'))
            
            # Remove user's tokens from active_tokens collection
            db.active_tokens.delete_many({'payroll_id': payroll_id})
            
            logger.info(f"All tokens for user {payroll_id} have been revoked")
            return True
            
        except Exception as e:
            logger.error(f"Error revoking user tokens: {str(e)}")
            return False
    
    def _is_token_revoked(self, jti: str) -> bool:
        """
        Check if a token is revoked.
        
        Args:
            jti: Token ID to check
            
        Returns:
            bool: True if token is revoked, False otherwise
        """
        # Check in-memory cache first for performance
        if jti in self.token_cache:
            return True
        
        # Check in database
        db = self._get_db()
        revoked = db.revoked_tokens.find_one({'jti': jti})
        
        # Update cache if found
        if revoked:
            self.token_cache[jti] = True
            return True
        
        return False
    
    def _get_db(self):
        """Get MongoDB database connection."""
        if hasattr(current_app, 'mongo'):
            return current_app.mongo.db
        elif 'mongo' in g:
            return g.mongo.db
        else:
            # Create a new connection
            client = MongoClient(current_app.config['MONGO_URI'])
            db = client[current_app.config['MONGO_DBNAME']]
            return db
    
    def _maybe_cleanup_expired_tokens(self):
        """Periodically clean up expired tokens based on cleanup interval."""
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_expired_tokens()
            self.last_cleanup = current_time
    
    def _cleanup_expired_tokens(self):
        """Remove expired tokens from revocation list."""
        try:
            db = self._get_db()
            result = db.revoked_tokens.delete_many({
                'expires_at': {'$lt': datetime.utcnow()}
            })
            
            # Clear in-memory cache
            self.token_cache = {}
            
            logger.info(f"Cleaned up {result.deleted_count} expired tokens")
            
        except Exception as e:
            logger.error(f"Error cleaning up expired tokens: {str(e)}")


# Helper function to initialize token manager
def init_token_manager(app):
    """
    Initialize the Token Manager with the application context.
    
    Args:
        app: Flask application instance
    
    Returns:
        TokenManager: Initialized token manager instance
    """
    token_manager = TokenManager(app)
    app.token_manager = token_manager
    return token_manager
