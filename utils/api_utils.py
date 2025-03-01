"""
API integration utilities for making external API calls and managing API authentication.
Provides standardized functions for API operations with robust error handling.
"""
import json
import logging
import time
import uuid
import hmac
import hashlib
import base64
import requests
from datetime import datetime, timedelta
from flask import current_app, request, g
from requests.exceptions import RequestException, Timeout, ConnectionError
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Default request timeout (seconds)
DEFAULT_TIMEOUT = 30

# Default retry settings
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 1  # seconds
DEFAULT_RETRY_BACKOFF_FACTOR = 2

# API key settings
API_KEY_MIN_LENGTH = 16
API_KEY_HEADER_NAME = 'X-API-Key'

def get_api_db():
    """
    Get the MongoDB collection for API data.
    
    Returns:
        MongoDB collection or None if not configured
    """
    if hasattr(current_app, 'mongo') and hasattr(current_app.mongo, 'db'):
        return current_app.mongo.db.api_logs
    return None

def call_external_api(url, method='GET', params=None, data=None, json_data=None, headers=None, 
                     auth=None, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=True,
                     retry_on_failure=True, max_retries=DEFAULT_MAX_RETRIES, 
                     retry_delay=DEFAULT_RETRY_DELAY, retry_backoff_factor=DEFAULT_RETRY_BACKOFF_FACTOR,
                     log_request=True):
    """
    Make a call to an external API with retry logic and error handling.
    
    Args:
        url (str): API endpoint URL
        method (str, optional): HTTP method. Defaults to 'GET'.
        params (dict, optional): Query parameters. Defaults to None.
        data (dict, optional): Form data. Defaults to None.
        json_data (dict, optional): JSON data. Defaults to None.
        headers (dict, optional): HTTP headers. Defaults to None.
        auth (tuple, optional): Authentication credentials (username, password). Defaults to None.
        timeout (int, optional): Request timeout in seconds. Defaults to DEFAULT_TIMEOUT.
        verify (bool, optional): Verify SSL certificates. Defaults to True.
        allow_redirects (bool, optional): Follow redirects. Defaults to True.
        retry_on_failure (bool, optional): Retry failed requests. Defaults to True.
        max_retries (int, optional): Maximum number of retry attempts. Defaults to DEFAULT_MAX_RETRIES.
        retry_delay (int, optional): Initial delay between retries in seconds. Defaults to DEFAULT_RETRY_DELAY.
        retry_backoff_factor (int, optional): Multiplicative factor for retry delay. Defaults to DEFAULT_RETRY_BACKOFF_FACTOR.
        log_request (bool, optional): Log the API request. Defaults to True.
        
    Returns:
        tuple: (Response object, error message)
    """
    method = method.upper()
    
    # Initialize or update headers
    if headers is None:
        headers = {}
    
    # Add default headers if not present
    if 'User-Agent' not in headers:
        headers['User-Agent'] = f'LeRepertoire/1.0'
    
    if method in ['POST', 'PUT', 'PATCH'] and json_data is not None and 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'
    
    # Generate a unique request ID for tracking
    request_id = str(uuid.uuid4())
    
    # Sanitize request data for logging (remove sensitive information)
    safe_params = _sanitize_data(params) if params else None
    safe_data = _sanitize_data(data) if data else None
    safe_json = _sanitize_data(json_data) if json_data else None
    safe_headers = _sanitize_headers(headers) if headers else None
    
    # Log the request if enabled
    if log_request:
        log_api_usage(
            url=url,
            method=method,
            params=safe_params,
            body=safe_json or safe_data,
            headers=safe_headers,
            request_id=request_id
        )
    
    # Initialize retry counter
    attempts = 0
    current_delay = retry_delay
    start_time = time.time()
    
    while True:
        attempts += 1
        
        try:
            # Make the request
            response = requests.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json_data,
                headers=headers,
                auth=auth,
                timeout=timeout,
                verify=verify,
                allow_redirects=allow_redirects
            )
            
            # Calculate request duration
            duration = time.time() - start_time
            
            # Log the response
            if log_request:
                logger.info(f"API request {request_id} completed in {duration:.3f}s with status {response.status_code}")
                
                # Log response for debugging (truncated for large responses)
                response_text = response.text[:1000] + '...' if len(response.text) > 1000 else response.text
                logger.debug(f"API response {request_id}: {response_text}")
                
                # Update API log with response
                _update_api_log(
                    request_id=request_id,
                    status_code=response.status_code,
                    response_time=duration,
                    response_body=response.text[:10000]  # Limit stored response size
                )
            
            # Return the response and None for error
            return response, None
            
        except (ConnectionError, Timeout) as e:
            # Network error or timeout
            error_msg = f"API request failed: {str(e)}"
            logger.warning(f"API request {request_id} attempt {attempts}/{max_retries} failed: {error_msg}")
            
            # Update API log with error
            if log_request:
                _update_api_log(
                    request_id=request_id,
                    status_code=0,
                    response_time=time.time() - start_time,
                    error=error_msg
                )
            
            # Check if we should retry
            if retry_on_failure and attempts < max_retries:
                # Calculate backoff delay
                time.sleep(current_delay)
                current_delay *= retry_backoff_factor
                continue
            
            # Max retries reached or retry disabled
            return None, error_msg
            
        except RequestException as e:
            # Other request exceptions
            error_msg = f"API request error: {str(e)}"
            logger.error(f"API request {request_id} failed: {error_msg}")
            
            # Update API log with error
            if log_request:
                _update_api_log(
                    request_id=request_id,
                    status_code=0,
                    response_time=time.time() - start_time,
                    error=error_msg
                )
            
            return None, error_msg
            
        except Exception as e:
            # Unexpected error
            error_msg = f"Unexpected error in API request: {str(e)}"
            logger.error(f"API request {request_id} failed with unexpected error: {error_msg}")
            
            # Update API log with error
            if log_request:
                _update_api_log(
                    request_id=request_id,
                    status_code=0,
                    response_time=time.time() - start_time,
                    error=error_msg
                )
            
            return None, error_msg

def handle_api_response(response, error=None, expected_status_codes=None, parse_json=True):
    """
    Process an API response with standardized error handling.
    
    Args:
        response: Response object from call_external_api
        error (str, optional): Error message if request failed. Defaults to None.
        expected_status_codes (list, optional): List of expected status codes. Defaults to [200].
        parse_json (bool, optional): Parse response as JSON. Defaults to True.
        
    Returns:
        tuple: (success flag, response data, error message)
    """
    # Set default expected status codes
    if expected_status_codes is None:
        expected_status_codes = [200]
    
    # If there was an error making the request
    if error:
        return False, None, error
    
    # If no response was returned
    if response is None:
        return False, None, "No response received"
    
    # Check if status code is expected
    if response.status_code not in expected_status_codes:
        error_msg = f"Unexpected status code: {response.status_code}"
        
        # Try to extract error details from response
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                # Look for common error fields
                for error_field in ['error', 'message', 'error_message', 'description', 'detail']:
                    if error_field in error_data:
                        error_msg = f"{error_msg} - {error_data[error_field]}"
                        break
        except:
            # Fall back to response text if JSON parsing fails
            if response.text:
                error_msg = f"{error_msg} - {response.text[:200]}"
        
        logger.warning(f"API response error: {error_msg}")
        return False, response, error_msg
    
    # Parse response as JSON if requested
    if parse_json:
        try:
            data = response.json()
            return True, data, None
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON response: {str(e)}"
            logger.warning(error_msg)
            return False, response, error_msg
    
    # Return raw response if JSON parsing is not requested
    return True, response, None

def authenticate_api_request(required_permissions=None):
    """
    Authenticate an incoming API request.
    
    Args:
        required_permissions (list, optional): List of required permissions. Defaults to None.
        
    Returns:
        tuple: (success flag, user_id or None, error_message or None)
    """
    # Check for API key in header or query parameter
    api_key = request.headers.get(API_KEY_HEADER_NAME) or request.args.get('api_key')
    
    if not api_key:
        logger.warning("API request without API key")
        return False, None, "Missing API key"
    
    # Validate API key
    is_valid, user_id, permissions = validate_api_key(api_key)
    
    if not is_valid:
        logger.warning(f"Invalid API key: {api_key[:5]}...")
        return False, None, "Invalid API key"
    
    # Check permissions if required
    if required_permissions and permissions:
        missing_permissions = [perm for perm in required_permissions if perm not in permissions]
        
        if missing_permissions:
            logger.warning(f"API key missing required permissions: {', '.join(missing_permissions)}")
            return False, user_id, f"Insufficient permissions: missing {', '.join(missing_permissions)}"
    
    # Set authenticated user in request context
    g.api_authenticated = True
    g.api_user_id = user_id
    g.api_permissions = permissions
    
    return True, user_id, None

def log_api_usage(url, method=None, params=None, body=None, headers=None, response=None, 
                 status_code=None, response_time=None, error=None, user_id=None, request_id=None):
    """
    Log an API request and response for monitoring and debugging.
    
    Args:
        url (str): API endpoint URL
        method (str, optional): HTTP method. Defaults to None.
        params (dict, optional): Query parameters. Defaults to None.
        body (dict, optional): Request body. Defaults to None.
        headers (dict, optional): HTTP headers. Defaults to None.
        response (str, optional): Response body. Defaults to None.
        status_code (int, optional): HTTP status code. Defaults to None.
        response_time (float, optional): Response time in seconds. Defaults to None.
        error (str, optional): Error message. Defaults to None.
        user_id (str, optional): User ID. Defaults to None.
        request_id (str, optional): Request ID. Defaults to None.
        
    Returns:
        str: Log entry ID or None if logging failed
    """
    api_db = get_api_db()
    if not api_db:
        logger.debug("API database not configured, skipping API usage logging")
        return None
    
    try:
        # Generate a request ID if none provided
        if not request_id:
            request_id = str(uuid.uuid4())
        
        # Extract domain from URL
        domain = None
        if url:
            try:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
            except:
                pass
        
        # Get user ID from context if not provided
        if user_id is None and hasattr(g, 'user') and hasattr(g.user, 'id'):
            user_id = g.user.id
        
        # Create log entry
        log_entry = {
            'request_id': request_id,
            'timestamp': datetime.utcnow(),
            'url': url,
            'domain': domain,
            'method': method,
            'params': params,
            'body': body,
            'headers': headers,
            'status_code': status_code,
            'response_time': response_time,
            'response': response,
            'error': error,
            'user_id': user_id,
            'ip_address': request.remote_addr if request else None
        }
        
        # Insert log entry
        result = api_db.insert_one(log_entry)
        
        if result and result.inserted_id:
            return request_id
        
        return None
    except Exception as e:
        logger.error(f"Error logging API usage: {str(e)}")
        return None

def _update_api_log(request_id, status_code=None, response_time=None, response_body=None, error=None):
    """
    Update an existing API log entry with response information.
    
    Args:
        request_id (str): Request ID
        status_code (int, optional): HTTP status code. Defaults to None.
        response_time (float, optional): Response time in seconds. Defaults to None.
        response_body (str, optional): Response body. Defaults to None.
        error (str, optional): Error message. Defaults to None.
        
    Returns:
        bool: True if update was successful, False otherwise
    """
    api_db = get_api_db()
    if not api_db:
        return False
    
    try:
        update_data = {
            'updated_at': datetime.utcnow()
        }
        
        if status_code is not None:
            update_data['status_code'] = status_code
            
        if response_time is not None:
            update_data['response_time'] = response_time
            
        if response_body is not None:
            update_data['response'] = response_body
            
        if error is not None:
            update_data['error'] = error
        
        result = api_db.update_one(
            {'request_id': request_id},
            {'$set': update_data}
        )
        
        return result.modified_count > 0
    except Exception as e:
        logger.error(f"Error updating API log: {str(e)}")
        return False

def validate_api_key(api_key):
    """
    Validate an API key and retrieve associated permissions.
    
    Args:
        api_key (str): API key to validate
        
    Returns:
        tuple: (is_valid, user_id, permissions)
    """
    # Basic validation
    if not api_key or len(api_key) < API_KEY_MIN_LENGTH:
        return False, None, None
    
    try:
        # Check if we have a database connection
        if hasattr(current_app, 'mongo') and hasattr(current_app.mongo, 'db'):
            db = current_app.mongo.db
            
            # Look up API key in database
            api_key_record = db.api_keys.find_one({
                'key': api_key,
                'active': True,
                'expiry_date': {'$gt': datetime.utcnow()}
            })
            
            if api_key_record:
                # Check if key has been revoked
                if api_key_record.get('revoked', False):
                    logger.warning(f"Revoked API key used: {api_key[:5]}...")
                    return False, None, None
                
                # Get user ID and permissions
                user_id = api_key_record.get('user_id')
                permissions = api_key_record.get('permissions', [])
                
                # Update last used timestamp
                db.api_keys.update_one(
                    {'_id': api_key_record['_id']},
                    {'$set': {'last_used': datetime.utcnow()}}
                )
                
                return True, user_id, permissions
            
            # If using the permanent system API key from config
            system_api_key = current_app.config.get('SYSTEM_API_KEY')
            if system_api_key and api_key == system_api_key:
                return True, 'system', ['*']  # System has all permissions
        
        # Check for test mode API key
        if current_app.config.get('TESTING', False) and api_key == 'test_api_key':
            return True, 'test_user', ['*']
        
        return False, None, None
    except Exception as e:
        logger.error(f"Error validating API key: {str(e)}")
        return False, None, None

def _sanitize_data(data):
    """
    Sanitize data by removing sensitive information.
    
    Args:
        data (dict): Data to sanitize
        
    Returns:
        dict: Sanitized data
    """
    if not data or not isinstance(data, dict):
        return data
    
    # Create a copy to avoid modifying the original
    sanitized = data.copy()
    
    # Sensitive fields to mask
    sensitive_fields = [
        'password', 'token', 'secret', 'key', 'auth', 'credentials', 
        'authorization', 'api_key', 'apikey', 'access_token', 'refresh_token',
        'credit_card', 'card_number', 'cvv', 'cvc', 'pin', 'ssn', 'social_security'
    ]
    
    # Check for sensitive fields at any level
    for key in list(sanitized.keys()):
        lower_key = key.lower()
        
        # Check if this is a sensitive field
        if any(sensitive in lower_key for sensitive in sensitive_fields):
            sanitized[key] = '***REDACTED***'
        elif isinstance(sanitized[key], dict):
            # Recursively sanitize nested dictionaries
            sanitized[key] = _sanitize_data(sanitized[key])
    
    return sanitized

def _sanitize_headers(headers):
    """
    Sanitize HTTP headers by removing sensitive information.
    
    Args:
        headers (dict): Headers to sanitize
        
    Returns:
        dict: Sanitized headers
    """
    if not headers or not isinstance(headers, dict):
        return headers
    
    # Create a copy to avoid modifying the original
    sanitized = headers.copy()
    
    # Sensitive header fields to mask
    sensitive_headers = [
        'authorization', 'x-api-key', 'api-key', 'auth', 'token', 'secret',
        'cookie', 'x-auth-token', 'x-csrf-token', 'access-token', 'refresh-token'
    ]
    
    # Check for sensitive headers
    for key in list(sanitized.keys()):
        lower_key = key.lower()
        
        # Check if this is a sensitive header
        if any(sensitive in lower_key for sensitive in sensitive_headers):
            sanitized[key] = '***REDACTED***'
    
    return sanitized

def generate_hmac_signature(secret_key, message, hash_algorithm='sha256'):
    """
    Generate an HMAC signature for API request authentication.
    
    Args:
        secret_key (str): Secret key for HMAC generation
        message (str): Message to sign
        hash_algorithm (str, optional): Hash algorithm to use. Defaults to 'sha256'.
        
    Returns:
        str: Base64 encoded HMAC signature
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    if isinstance(secret_key, str):
        secret_key = secret_key.encode('utf-8')
    
    # Create HMAC signature
    if hash_algorithm.lower() == 'sha256':
        signature = hmac.new(secret_key, message, hashlib.sha256).digest()
    elif hash_algorithm.lower() == 'sha512':
        signature = hmac.new(secret_key, message, hashlib.sha512).digest()
    elif hash_algorithm.lower() == 'md5':
        signature = hmac.new(secret_key, message, hashlib.md5).digest()
    else:
        # Default to SHA-256
        signature = hmac.new(secret_key, message, hashlib.sha256).digest()
    
    # Encode as Base64
    return base64.b64encode(signature).decode('utf-8')

def verify_hmac_signature(secret_key, message, signature, hash_algorithm='sha256'):
    """
    Verify an HMAC signature for API request authentication.
    
    Args:
        secret_key (str): Secret key for HMAC verification
        message (str): Original message
        signature (str): Base64 encoded HMAC signature to verify
        hash_algorithm (str, optional): Hash algorithm to use. Defaults to 'sha256'.
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Generate expected signature
    expected_signature = generate_hmac_signature(secret_key, message, hash_algorithm)
    
    # Compare signatures using constant-time comparison
    return hmac.compare_digest(expected_signature, signature)
