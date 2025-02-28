# ------------------------------------------------------------
# utils/defense/validation_utils.py
# ------------------------------------------------------------
import re
import uuid
from datetime import datetime
import logging
from functools import wraps
from flask import request, jsonify

logger = logging.getLogger(__name__)

def validate_request_data(required_fields):
    """
    Decorator to validate required fields in request data
    
    Usage:
    @validate_request_data(['payroll_id', 'password'])
    def login():
        # Your route logic here
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                data = request.get_json()
                if not data:
                    return jsonify({
                        "success": False,
                        "message": "No data provided"
                    }), 400

                missing_fields = [
                    field for field in required_fields 
                    if not data.get(field)
                ]

                if missing_fields:
                    return jsonify({
                        "success": False,
                        "message": f"Missing required fields: {', '.join(missing_fields)}"
                    }), 400

                return f(*args, **kwargs)

            except Exception as e:
                logger.error(f"Request validation error: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Invalid request data"
                }), 400

        return decorated_function
    return decorator

def validate_id_format(id_str, prefix):
    """
    Validate ID format (e.g., USR-XX123456, BUS-XXXXXXXX, etc.)
    """
    if not isinstance(id_str, str):
        return False
        
    patterns = {
        'USR': r'^USR-[A-Z]{2}[0-9]{6}$',
        'BUS': r'^BUS-[A-Z0-9]{8}$',
        'VEN': r'^VEN-[A-Z0-9]{8}$',
        'WRK': r'^WRK-[A-Z0-9]{8}$'
    }
    
    pattern = patterns.get(prefix)
    if not pattern:
        return False
        
    return bool(re.match(pattern, id_str))

def validate_uuid(uuid_str):
    """
    Validate UUID format
    """
    try:
        uuid.UUID(str(uuid_str))
        return True
    except (ValueError, AttributeError):
        return False

def validate_email(email):
    """
    Validate email format
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, str(email)))

def validate_date_format(date_str):
    """
    Validate date format (YYYY-MM-DD)
    """
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except (ValueError, TypeError):
        return False

def validate_phone_number(phone):
    """
    Validate phone number format
    """
    # Remove any spaces, dashes, or parentheses
    cleaned = re.sub(r'[\s\-\(\)]', '', str(phone))
    # Check if it matches international format
    return bool(re.match(r'^\+?[0-9]{10,15}$', cleaned))

def validate_required_fields(data, required_fields):
    """
    Validate presence of required fields in data
    Returns (is_valid, missing_fields)
    """
    if not isinstance(data, dict):
        return False, ["Data must be a dictionary"]
        
    missing = [field for field in required_fields if not data.get(field)]
    return len(missing) == 0, missing

def validate_field_length(value, min_length=None, max_length=None):
    """
    Validate field length
    """
    if not value:
        return False
        
    length = len(str(value))
    
    if min_length and length < min_length:
        return False
    if max_length and length > max_length:
        return False
        
    return True

def validate_numeric_range(value, min_value=None, max_value=None):
    """
    Validate numeric value range
    """
    try:
        num = float(value)
        if min_value is not None and num < min_value:
            return False
        if max_value is not None and num > max_value:
            return False
        return True
    except (ValueError, TypeError):
        return False

def log_validation_error(context, error_message):
    """
    Log validation errors
    """
    logger.error(f"Validation Error - {context}: {error_message}")

def sanitize_filename(filename):
    """
    Sanitize filename to prevent directory traversal
    """
    return re.sub(r'[^a-zA-Z0-9._-]', '', filename)

def validate_business_data(business_data):
    """
    Validate business data structure
    Returns (is_valid, error_messages)
    """
    errors = []
    
    # Required fields
    required = ['name', 'venue_type']
    missing = [f for f in required if not business_data.get(f)]
    if missing:
        errors.append(f"Missing required fields: {', '.join(missing)}")
    
    # Name validation
    name = business_data.get('name', '')
    if not validate_field_length(name, min_length=2, max_length=100):
        errors.append("Business name must be between 2 and 100 characters")
    
    # Venue type validation
    venue_type = business_data.get('venue_type', '')
    valid_types = ['restaurant', 'cafe', 'bar', 'hotel', 'other']
    if venue_type not in valid_types:
        errors.append(f"Invalid venue type. Must be one of: {', '.join(valid_types)}")
    
    return len(errors) == 0, errors

def validate_venue_data(venue_data):
    """
    Validate venue data structure
    Returns (is_valid, error_messages)
    """
    errors = []
    
    # Required fields
    required = ['name', 'address']
    missing = [f for f in required if not venue_data.get(f)]
    if missing:
        errors.append(f"Missing required fields: {', '.join(missing)}")
    
    # Name validation
    name = venue_data.get('name', '')
    if not validate_field_length(name, min_length=2, max_length=100):
        errors.append("Venue name must be between 2 and 100 characters")
    
    # Address validation
    address = venue_data.get('address', '')
    if not validate_field_length(address, min_length=5, max_length=200):
        errors.append("Address must be between 5 and 200 characters")
    
    # Contact validation (if provided)
    contact = venue_data.get('contact')
    if contact and not validate_phone_number(contact):
        errors.append("Invalid contact number format")
    
    return len(errors) == 0, errors

def validate_work_area_data(work_area_data):
    """
    Validate work area data structure
    Returns (is_valid, error_messages)
    """
    errors = []
    
    # Required fields
    required = ['name']
    missing = [f for f in required if not work_area_data.get(f)]
    if missing:
        errors.append(f"Missing required fields: {', '.join(missing)}")
    
    # Name validation
    name = work_area_data.get('name', '')
    if not validate_field_length(name, min_length=2, max_length=50):
        errors.append("Work area name must be between 2 and 50 characters")
    
    # Description validation (if provided)
    description = work_area_data.get('description', '')
    if description and not validate_field_length(description, max_length=500):
        errors.append("Description must not exceed 500 characters")
    
    return len(errors) == 0, errors
