# ------------------------------------------------------------
#                   routes/auth/auth_routes.py
# ------------------------------------------------------------
from flask import Blueprint, request, jsonify, current_app, g, session
from functools import wraps
import jwt
from datetime import datetime, timedelta
import logging

# Import additional utilities (preserved from original)
from utils.validation_utils import validate_request_data
from utils.security_utils import generate_random_string
from utils.google_utils import validate_google_token, get_google_service
from utils.business_utils import lookup_business
from utils.time_utils import generate_timestamp
from utils.rate_limiter import RateLimiter

# Import our updated authentication utilities
from utils.auth.auth_utils import validate_payroll_id, check_password

# Import AuditLogger for audit events
from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

auth = Blueprint('auth', __name__)

# Initialize rate limiter for login attempts
login_limiter = RateLimiter(
    max_attempts=5,
    window_seconds=300,  # 5 minutes
    block_seconds=900    # 15 minutes
)

class AuthError(Exception):
    """Custom exception for authentication errors"""
    def __init__(self, message, status_code=401):
        self.message = message
        self.status_code = status_code

def create_session_token(user):
    """
    Create a JWT token containing essential user data.
    Uses the updated user document structure:
      - payroll_id: stored at top-level
      - work_email: stored as 'work_email'
      - role: stored at top-level
      - business_id: stored as 'company_id'
      - venue_id: stored at top-level
      - work_area_id: stored at top-level
    """
    try:
        payload = {
            'payroll_id': user['payroll_id'],
            'email_work': user['work_email'],
            'role': user['role'],
            'business_id': user['company_id'],
            'venue_id': user['venue_id'],
            'work_area_id': user['work_area_id'],
            'exp': datetime.utcnow() + timedelta(hours=8),
            'iat': datetime.utcnow()
        }
        return jwt.encode(
            payload, 
            current_app.config['SECRET_KEY'], 
            algorithm='HS256'
        )
    except Exception as e:
        logger.error(f"Token creation failed: {str(e)}")
        raise AuthError("Failed to create authentication token")

def verify_token(token):
    """
    Verify and decode JWT token.
    """
    try:
        return jwt.decode(
            token, 
            current_app.config['SECRET_KEY'], 
            algorithms=['HS256']
        )
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired")
    except jwt.InvalidTokenError:
        raise AuthError("Invalid token")

def login_required(f):
    """
    Decorator to protect routes requiring authentication.
    Checks the Authorization header for a valid JWT token,
    verifies that the user exists and is active, and populates
    Flask's global 'g' with token payload and full user document.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                raise AuthError("No authentication token provided")

            token = auth_header.replace('Bearer ', '')
            payload = verify_token(token)
            
            # Verify that the user exists and is active using updated fields
            user = current_app.mongo.db.business_users.find_one({
                "payroll_id": payload['payroll_id'],
                "status": {"$ne": "inactive"}
            })
            
            if not user:
                raise AuthError("User account is no longer active")
            
            g.user = payload
            g.current_user = user  # Store full user document for route handlers
            return f(*args, **kwargs)
            
        except AuthError as e:
            return jsonify({
                "success": False,
                "message": e.message
            }), e.status_code
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "Authentication failed"
            }), 401
            
    return decorated_function

@auth.route("/auth/login", methods=['POST'])
def login():
    """
    Handle user login with payroll ID and password.
    
    Expected JSON payload:
      {
         "payroll_id": "D{work_area_letter}-XXXXXX",
         "password": "<plaintext_password>"
      }
    
    Features:
      - Validates required fields.
      - Applies rate limiting to mitigate brute-force attacks.
      - Validates the payroll ID format using the updated function.
      - Retrieves the user from 'business_users' collection.
      - Verifies the plaintext password against the stored hash.
      - Clears rate limiting on successful login.
      - Creates a JWT token containing essential user data.
      - Updates the last login timestamp.
      - Logs the successful login event.
      - Returns the token and a subset of user data.
    """
    try:
        data = request.get_json()
        payroll_id = data.get('payroll_id')
        password = data.get('password')

        # Validate input
        if not payroll_id or not password:
            return jsonify({
                "success": False,
                "message": "Please provide both payroll ID and password"
            }), 400

        # Check rate limiting
        if login_limiter.is_blocked(payroll_id):
            logger.warning(f"Rate limit exceeded for payroll ID: {payroll_id}")
            return jsonify({
                "success": False,
                "message": "Too many failed attempts. Please try again later."
            }), 429

        # Validate payroll ID format using the updated function
        if not validate_payroll_id(payroll_id):
            login_limiter.record_attempt(payroll_id, success=False)
            return jsonify({
                "success": False,
                "message": "Invalid payroll ID format"
            }), 400

        # Find user in MongoDB using the updated document structure
        user = current_app.mongo.db.business_users.find_one({
            "payroll_id": payroll_id,
            "status": {"$ne": "inactive"}
        })

        if not user:
            login_limiter.record_attempt(payroll_id, success=False)
            logger.warning(f"Login attempt with non-existent payroll ID: {payroll_id}")
            return jsonify({
                "success": False,
                "message": "Invalid payroll ID or password"
            }), 401

        # Verify password using the imported utility function
        if not check_password(user['password'], password):
            login_limiter.record_attempt(payroll_id, success=False)
            logger.warning(f"Failed login attempt for payroll ID: {payroll_id}")
            return jsonify({
                "success": False,
                "message": "Invalid payroll ID or password"
            }), 401

        # Clear rate limiting on successful login
        login_limiter.clear_attempts(payroll_id)

        # Create session token (JWT)
        token = create_session_token(user)

        # Update last login timestamp
        current_app.mongo.db.business_users.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "last_login": datetime.utcnow()
                }
            }
        )

        # Log successful login
        AuditLogger.log_event(
            'user_login',
            payroll_id,
            user.get('company_id', 'N/A'),
            'Successful login',
            ip_address=request.remote_addr
        )

        # Prepare user data for response
        user_data = {
            "payroll_id": user['payroll_id'],
            "email_work": user['work_email'],
            "name_first": user['first_name'],
            "name_preferred": user.get('preferred_name'),
            "role": user['role'],
            "permissions": user.get('permissions', []),
            "business_id": user['company_id'],
            "venue_id": user['venue_id'],
            "work_area_id": user['work_area_id']
        }

        return jsonify({
            "success": True,
            "token": token,
            "user": user_data
        })

    except AuthError as e:
        return jsonify({
            "success": False,
            "message": e.message
        }), e.status_code
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "An unexpected error occurred"
        }), 500

@auth.route("/auth/verify-token", methods=['POST'])
def verify_token_route():
    """
    Verify token validity and return user data.
    
    Expects the Authorization header in the format:
       Bearer <token>
       
    On success, returns the user data extracted from the token and database.
    """
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            raise AuthError("No token provided")

        token = auth_header.replace('Bearer ', '')
        payload = verify_token(token)

        # Verify that the user still exists and is active
        user = current_app.mongo.db.business_users.find_one({
            "payroll_id": payload['payroll_id'],
            "status": {"$ne": "inactive"}
        })

        if not user:
            raise AuthError("User account is no longer active")

        return jsonify({
            "success": True,
            "valid": True,
            "user": {
                "payroll_id": user['payroll_id'],
                "email_work": user['work_email'],
                "name_first": user['first_name'],
                "name_preferred": user.get('preferred_name'),
                "role": user['role'],
                "permissions": user.get('permissions', [])
            }
        })

    except AuthError as e:
        return jsonify({
            "success": False,
            "message": e.message
        }), e.status_code
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Token verification failed"
        }), 401

@auth.route("/auth/logout", methods=['POST'])
@login_required
def logout():
    """
    Handle user logout with audit logging.
    Requires a valid token via the login_required decorator.
    """
    try:
        # Log logout event using data stored in g.user and g.current_user
        AuditLogger.log_event(
            'user_logout',
            g.user['payroll_id'],
            g.current_user.get('company_id', 'N/A'),
            'User logged out',
            ip_address=request.remote_addr
        )
        
        # Clear session
        session.clear()
        
        return jsonify({
            "success": True,
            "message": "Successfully logged out"
        })
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Logout failed"
        }), 500

# Error handlers
@auth.errorhandler(AuthError)
def handle_auth_error(error):
    """Handle authentication errors."""
    return jsonify({
        "success": False,
        "message": error.message
    }), error.status_code

@auth.errorhandler(Exception)
def handle_generic_error(error):
    """Handle generic errors."""
    logger.error(f"Unexpected error: {str(error)}")
    return jsonify({
        "success": False,
        "message": "An unexpected error occurred"
    }), 500
