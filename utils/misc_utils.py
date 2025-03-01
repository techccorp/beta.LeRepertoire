"""
Miscellaneous utility functions for common operations.
Provides general-purpose helper functions used across the application.
"""
import json
import logging
import re
import unicodedata
import uuid
from datetime import datetime
from decimal import Decimal
from urllib.parse import quote

logger = logging.getLogger(__name__)

def generate_slug(text, max_length=80):
    """
    Generate a URL-friendly slug from a string.
    
    Args:
        text (str): Text to convert to slug
        max_length (int, optional): Maximum length of slug. Defaults to 80.
        
    Returns:
        str: URL-friendly slug
    """
    if not text:
        return ""
        
    try:
        # Convert to lowercase and remove accents
        text = str(text).lower()
        text = unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('ascii')
        
        # Replace non-alphanumeric characters with hyphens
        text = re.sub(r'[^a-z0-9\-]', '-', text)
        
        # Replace multiple hyphens with a single hyphen
        text = re.sub(r'-+', '-', text)
        
        # Remove leading and trailing hyphens
        text = text.strip('-')
        
        # Truncate to maximum length
        if max_length > 0 and len(text) > max_length:
            text = text[:max_length].rstrip('-')
            
        return text
    except Exception as e:
        logger.error(f"Error generating slug from '{text}': {str(e)}")
        return uuid.uuid4().hex[:8]  # Fallback to random slug

def format_currency(amount, currency_code='AUD', locale='en_AU'):
    """
    Format a monetary value as a currency string.
    
    Args:
        amount (Decimal or float): Amount to format
        currency_code (str, optional): Currency code (e.g., 'AUD', 'USD'). Defaults to 'AUD'.
        locale (str, optional): Locale code (e.g., 'en_AU', 'en_US'). Defaults to 'en_AU'.
        
    Returns:
        str: Formatted currency string
    """
    try:
        # Simple fallback formatter without external dependencies
        if isinstance(amount, str):
            try:
                amount = Decimal(amount)
            except:
                amount = float(amount)
                
        # Ensure amount is a number
        if not isinstance(amount, (int, float, Decimal)):
            return f"{currency_code} -"
            
        # Format with 2 decimal places
        formatted = f"{float(amount):,.2f}"
        
        # Add currency symbol
        currency_symbols = {
            'AUD': 'A$',
            'USD': '$',
            'EUR': '€',
            'GBP': '£',
            'JPY': '¥',
            'NZD': 'NZ$',
            'SGD': 'S$',
            'CAD': 'C$',
        }
        
        symbol = currency_symbols.get(currency_code, currency_code)
        return f"{symbol}{formatted}"
    except Exception as e:
        logger.error(f"Error formatting currency {amount} {currency_code}: {str(e)}")
        return f"{currency_code} {amount}"

def parse_json(json_string, default=None):
    """
    Parse a JSON string to a Python object with error handling.
    
    Args:
        json_string (str): JSON string to parse
        default (any, optional): Default value if parsing fails. Defaults to None.
        
    Returns:
        any: Parsed Python object or default value
    """
    if not json_string:
        return default
        
    try:
        return json.loads(json_string)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return default
    except Exception as e:
        logger.error(f"Unexpected error parsing JSON: {str(e)}")
        return default

def format_json(obj, pretty=True, default=None):
    """
    Format a Python object as a JSON string.
    
    Args:
        obj (any): Python object to format as JSON
        pretty (bool, optional): Whether to pretty-print the JSON. Defaults to True.
        default (function, optional): Function to convert non-serializable objects. Defaults to None.
        
    Returns:
        str: JSON string or empty string if formatting fails
    """
    if obj is None:
        return ""
        
    try:
        if pretty:
            return json.dumps(obj, indent=2, sort_keys=True, default=default)
        else:
            return json.dumps(obj, default=default)
    except TypeError as e:
        logger.error(f"Error formatting JSON (type error): {str(e)}")
        return ""
    except Exception as e:
        logger.error(f"Unexpected error formatting JSON: {str(e)}")
        return ""

def get_current_timestamp(format_str=None):
    """
    Get the current timestamp in a standardized format.
    
    Args:
        format_str (str, optional): Format string for strftime. Defaults to None for ISO 8601.
        
    Returns:
        str: Formatted timestamp string or datetime object if format_str is None
    """
    now = datetime.utcnow()
    
    if format_str:
        return now.strftime(format_str)
    else:
        return now.isoformat()

def generate_unique_id(prefix=None, length=10):
    """
    Generate a unique ID.
    
    Args:
        prefix (str, optional): Prefix for the ID. Defaults to None.
        length (int, optional): Length of the random part. Defaults to 10.
        
    Returns:
        str: Unique ID
    """
    # Generate random part
    random_part = uuid.uuid4().hex[:length]
    
    # Add prefix if provided
    if prefix:
        return f"{prefix}_{random_part}"
    else:
        return random_part

def truncate_string(text, max_length=100, suffix='...'):
    """
    Truncate a string to a maximum length.
    
    Args:
        text (str): String to truncate
        max_length (int, optional): Maximum length. Defaults to 100.
        suffix (str, optional): Suffix to add when truncated. Defaults to '...'.
        
    Returns:
        str: Truncated string
    """
    if not text:
        return ""
        
    text = str(text)
    
    if len(text) <= max_length:
        return text
    else:
        return text[:max_length - len(suffix)] + suffix

def strip_html_tags(html):
    """
    Remove HTML tags from a string.
    
    Args:
        html (str): HTML string
        
    Returns:
        str: String with HTML tags removed
    """
    if not html:
        return ""
        
    try:
        # Simple regex to strip HTML tags
        return re.sub(r'<[^>]+>', '', html)
    except Exception as e:
        logger.error(f"Error stripping HTML tags: {str(e)}")
        return html

def url_encode(text):
    """
    URL-encode a string.
    
    Args:
        text (str): String to URL-encode
        
    Returns:
        str: URL-encoded string
    """
    if not text:
        return ""
        
    try:
        return quote(str(text), safe='')
    except Exception as e:
        logger.error(f"Error URL-encoding string: {str(e)}")
        return text

def format_file_size(size_bytes):
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes (int): File size in bytes
        
    Returns:
        str: Formatted file size
    """
    try:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    except Exception as e:
        logger.error(f"Error formatting file size: {str(e)}")
        return f"{size_bytes} bytes"

def pluralize(count, singular, plural=None):
    """
    Return singular or plural form based on count.
    
    Args:
        count (int): Count to base pluralization on
        singular (str): Singular form
        plural (str, optional): Plural form. Defaults to None (append 's' to singular).
        
    Returns:
        str: Singular or plural form
    """
    if count == 1:
        return singular
    else:
        return plural if plural is not None else f"{singular}s"

def camel_to_snake(text):
    """
    Convert camelCase to snake_case.
    
    Args:
        text (str): camelCase string
        
    Returns:
        str: snake_case string
    """
    if not text:
        return ""
        
    try:
        # Insert underscore before uppercase letters
        result = re.sub(r'(?<!^)(?=[A-Z])', '_', text).lower()
        return result
    except Exception as e:
        logger.error(f"Error converting camelCase to snake_case: {str(e)}")
        return text

def snake_to_camel(text):
    """
    Convert snake_case to camelCase.
    
    Args:
        text (str): snake_case string
        
    Returns:
        str: camelCase string
    """
    if not text:
        return ""
        
    try:
        # Split by underscore and join with capitalization
        components = text.split('_')
        return components[0] + ''.join(x.title() for x in components[1:])
    except Exception as e:
        logger.error(f"Error converting snake_case to camelCase: {str(e)}")
        return text

def snake_to_title(text):
    """
    Convert snake_case to Title Case.
    
    Args:
        text (str): snake_case string
        
    Returns:
        str: Title Case string
    """
    if not text:
        return ""
        
    try:
        # Split by underscore and join with spaces and capitalization
        return ' '.join(word.capitalize() for word in text.split('_'))
    except Exception as e:
        logger.error(f"Error converting snake_case to Title Case: {str(e)}")
        return text

def is_valid_email(email):
    """
    Check if an email address is valid.
    
    Args:
        email (str): Email address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not email:
        return False
        
    try:
        # Simple regex for email validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    except Exception as e:
        logger.error(f"Error validating email: {str(e)}")
        return False

def is_valid_url(url):
    """
    Check if a URL is valid.
    
    Args:
        url (str): URL to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not url:
        return False
        
    try:
        # Simple regex for URL validation
        pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url))
    except Exception as e:
        logger.error(f"Error validating URL: {str(e)}")
        return False

def merge_dicts(dict1, dict2, overwrite=True):
    """
    Merge two dictionaries.
    
    Args:
        dict1 (dict): First dictionary
        dict2 (dict): Second dictionary
        overwrite (bool, optional): Whether to overwrite existing keys. Defaults to True.
        
    Returns:
        dict: Merged dictionary
    """
    if not dict1:
        return dict2 or {}
        
    if not dict2:
        return dict1 or {}
        
    try:
        # Create a new dictionary with dict1 as the base
        result = dict1.copy()
        
        # Update with dict2 values
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                # Recursively merge nested dictionaries
                result[key] = merge_dicts(result[key], value, overwrite)
            elif key not in result or overwrite:
                # Add new key or overwrite existing key
                result[key] = value
                
        return result
    except Exception as e:
        logger.error(f"Error merging dictionaries: {str(e)}")
        return dict1

def generate_random_password(length=12, include_uppercase=True, include_digits=True, include_special=True):
    """
    Generate a random password.
    
    Args:
        length (int, optional): Password length. Defaults to 12.
        include_uppercase (bool, optional): Include uppercase letters. Defaults to True.
        include_digits (bool, optional): Include digits. Defaults to True.
        include_special (bool, optional): Include special characters. Defaults to True.
        
    Returns:
        str: Random password
    """
    import random
    import string
    
    try:
        # Define character sets
        chars = string.ascii_lowercase
        if include_uppercase:
            chars += string.ascii_uppercase
        if include_digits:
            chars += string.digits
        if include_special:
            chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
            
        # Generate password
        password = ''.join(random.choice(chars) for _ in range(length))
        return password
    except Exception as e:
        logger.error(f"Error generating random password: {str(e)}")
        return str(uuid.uuid4())[:length]  # Fallback to UUID
