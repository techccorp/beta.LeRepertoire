# ------------------------------------------------------------
# utils/auth/auth_utils.py
# ------------------------------------------------------------
import re
import bcrypt
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Union
import logging
from flask import current_app, Request

logger = logging.getLogger(__name__)

TOKEN_ALGORITHM = "HS256"
PAYROLL_ID_REGEX = r'^D[KBROFPSGWV]-\d{6}$'

def validate_payroll_id(payroll_id: str) -> bool:
    """Validate payroll ID format against current schema"""
    try:
        if not isinstance(payroll_id, str):
            return False
        return re.fullmatch(PAYROLL_ID_REGEX, payroll_id.strip().upper()) is not None
    except Exception as e:
        logger.error("Payroll ID validation error", exc_info=True)
        return False

def hash_password(password: str) -> str:
    """Secure password hashing with bcrypt"""
    try:
        if not password or len(password) < 8:
            raise ValueError("Invalid password length")
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    except Exception as e:
        logger.error("Password hashing failed", exc_info=True)
        raise

def check_password(stored_hash: str, password: str) -> bool:
    """Constant-time password verification"""
    try:
        return bcrypt.checkpw(
            password.encode('utf-8'),
            stored_hash.encode('utf-8')
        )
    except Exception as e:
        logger.error("Password check failed", exc_info=True)
        return False

def generate_token(user_data: Dict[str, Any], expiry_hours: int = 8) -> str:
    """JWT token generation with schema-compatible fields"""
    required_fields = [
        'payroll_id', 'work_email', 'role_name',
        'company_id', 'venue_id', 'work_area_id'
    ]
    
    for field in required_fields:
        if field not in user_data:
            logger.error(f"Missing required field for token: {field}")
            raise ValueError(f"Missing required field: {field}")

    try:
        payload = {
            'payroll_id': user_data['payroll_id'],
            'work_email': user_data['work_email'],
            'role_name': user_data['role_name'],
            'company_id': user_data['company_id'],
            'venue_id': user_data['venue_id'],
            'work_area_id': user_data['work_area_id'],
            'exp': datetime.utcnow() + timedelta(hours=expiry_hours),
            'iat': datetime.utcnow(),
            'iss': current_app.config.get('TOKEN_ISSUER', 'payroll_system')
        }
        
        return jwt.encode(
            payload,
            current_app.config['SECRET_KEY'],
            algorithm=TOKEN_ALGORITHM
        )
    except Exception as e:
        logger.critical("Token generation failure", exc_info=True)
        raise

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Comprehensive token verification with schema checks"""
    try:
        payload = jwt.decode(
            token,
            current_app.config['SECRET_KEY'],
            algorithms=[TOKEN_ALGORITHM],
            options={
                'require_iat': True,
                'verify_exp': True,
                'verify_iss': True,
                'issuer': current_app.config.get('TOKEN_ISSUER', 'payroll_system')
            }
        )
        
        if not validate_payroll_id(payload.get('payroll_id', '')):
            logger.warning("Invalid payroll ID in token")
            return None
            
        return payload
        
    except jwt.ExpiredSignatureError:
        logger.warning("Expired token attempt")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        logger.error("Token verification error", exc_info=True)
        return None

def extract_token_from_request(request: Request) -> Optional[str]:
    """Extract token from Authorization header with validation"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        logger.debug("No authorization header present")
        return None

    try:
        # Handle multiple authorization schemes
        parts = auth_header.split()
        if len(parts) == 2:
            scheme, token = parts
            if scheme.lower() != 'bearer':
                logger.warning(f"Unsupported auth scheme: {scheme}")
                return None
            return token.strip()
            
        if len(parts) == 1:
            return parts[0].strip()
            
        logger.warning("Malformed authorization header")
        return None

    except Exception as e:
        logger.error("Token extraction error", exc_info=True)
        return None

def get_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    """Secure user retrieval with schema validation"""
    try:
        payload = verify_token(token)
        if not payload:
            return None

        user = current_app.mongo.db.business_users.find_one({
            'payroll_id': payload['payroll_id'],
            'status': {'$ne': 'inactive'}
        })

        if not user:
            logger.warning(f"User not found for payroll ID: {payload['payroll_id']}")
            return None

        # Schema validation check
        required_fields = [
            'payroll_id', 'work_email', 'role_name',
            'company_id', 'venue_id', 'work_area_id'
        ]
        for field in required_fields:
            if field not in user:
                logger.error(f"User document missing required field: {field}")
                return None

        return user

    except Exception as e:
        logger.error("User retrieval failed", exc_info=True)
        return None
