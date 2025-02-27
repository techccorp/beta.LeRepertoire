"""
Authentication utility functions for the payroll application.
"""
import re
import bcrypt
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Union
import logging
from flask import current_app

logger = logging.getLogger(__name__)

def validate_payroll_id(payroll_id: str) -> bool:
    """
    Validate the format of a payroll ID.
    
    Valid format: D{work_area_letter}-{6 digits}
    Example: DK-308020 (Kitchen), DB-631353 (Bar)
    
    Args:
        payroll_id: The payroll ID to validate
        
    Returns:
        bool: True if the payroll ID is valid, False otherwise
    """
    # Check if the payroll ID matches the pattern
    pattern = r'^D[KBROFPSGW]-\d{6}$'
    return bool(re.match(pattern, payroll_id))

def hash_password(password: str) -> str:
    """
    Hash a password for secure storage.
    
    Args:
        password: The plaintext password to hash
        
    Returns:
        str: The hashed password
    """
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def check_password(stored_hash: str, password: str) -> bool:
    """
    Check if a plaintext password matches a stored hash.
    
    Args:
        stored_hash: The stored hashed password
        password: The plaintext password to check
        
    Returns:
        bool: True if the password matches, False otherwise
    """
    try:
        return bcrypt.checkpw(
            password.encode('utf-8'),
            stored_hash.encode('utf-8')
        )
    except Exception as e:
        logger.error(f"Password check error: {str(e)}")
        return False

def generate_token(user_data: Dict[str, Any], expiry_hours: int = 8) -> str:
    """
    Generate a JWT token for authentication.
    
    Args:
        user_data: Dictionary containing user information
        expiry_hours: Token expiry time in hours
        
    Returns:
        str: Encoded JWT token
    """
    try:
        # Create payload with user data and expiry
        payload = {
            # Essential user identifiers
            'payroll_id': user_data['payroll_id'],
            'email': user_data['work_email'],
            
            # Role and permission context
            'role': user_data['role'],
            
            # Business context
            'business_id': user_data['company_id'],
            'venue_id': user_data['venue_id'],
            'work_area_id': user_data['work_area_id'],
            
            # Token metadata
            'exp': datetime.utcnow() + timedelta(hours=expiry_hours),
            'iat': datetime.utcnow()
        }
        
        # Encode and return token
        return jwt.encode(
            payload,
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )
    except Exception as e:
        logger.error(f"Token generation error: {str(e)}")
        raise

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token to verify
        
    Returns:
        dict: Decoded token payload or None if invalid
    """
    try:
        # Decode and verify token
        return jwt.decode(
            token,
            current_app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        return None

def extract_token_from_request(request) -> Optional[str]:
    """
    Extract token from the Authorization header.
    
    Args:
        request: Flask request object
        
    Returns:
        str: Token or None if not found
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None
        
    # Handle both "Bearer token" and "token" formats
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == 'bearer':
        return parts[1]
    elif len(parts) == 1:
        return parts[0]
        
    return None

def get_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Get user details from a verified token.
    
    Args:
        token: JWT token
        
    Returns:
        dict: User data or None if token invalid or user not found
    """
    # Verify token
    payload = verify_token(token)
    if not payload:
        return None
        
    # Get user from database
    user = current_app.mongo.db.business_users.find_one({
        'payroll_id': payload['payroll_id']
    })
    
    return user
