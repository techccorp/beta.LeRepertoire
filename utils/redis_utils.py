"""
Redis utilities for caching and data operations.
Provides wrapper functions for common Redis operations.
"""
import json
import logging
from flask import current_app

logger = logging.getLogger(__name__)

def get_redis_client():
    """
    Get the Redis client from the Flask app context.
    
    Returns:
        Redis client instance or None if not configured
    """
    if hasattr(current_app, 'redis'):
        return current_app.redis
    return None

def set_cache(key, value, expiry=3600):
    """
    Set a value in Redis cache.
    
    Args:
        key (str): Cache key
        value (any): Value to cache (will be JSON serialized if not a string)
        expiry (int, optional): Expiry time in seconds. Defaults to 3600 (1 hour).
        
    Returns:
        bool: True if successful, False otherwise
    """
    redis_client = get_redis_client()
    if not redis_client:
        logger.debug("Redis not configured, skipping cache set")
        return False
        
    try:
        # Convert non-string values to JSON
        if not isinstance(value, str):
            value = json.dumps(value)
            
        # Set value with expiry
        return redis_client.setex(key, expiry, value)
    except Exception as e:
        logger.error(f"Redis set error: {str(e)}")
        return False

def get_cache(key):
    """
    Get a value from Redis cache.
    
    Args:
        key (str): Cache key
        
    Returns:
        any: Cached value or None if not found
    """
    redis_client = get_redis_client()
    if not redis_client:
        logger.debug("Redis not configured, skipping cache get")
        return None
        
    try:
        value = redis_client.get(key)
        
        # Try to parse JSON if it looks like JSON
        if value and value.startswith('{') and value.endswith('}'):
            try:
                return json.loads(value)
            except:
                pass
                
        return value
    except Exception as e:
        logger.error(f"Redis get error: {str(e)}")
        return None

def delete_cache(key):
    """
    Delete a value from Redis cache.
    
    Args:
        key (str): Cache key
        
    Returns:
        bool: True if successful, False otherwise
    """
    redis_client = get_redis_client()
    if not redis_client:
        logger.debug("Redis not configured, skipping cache delete")
        return False
        
    try:
        return bool(redis_client.delete(key))
    except Exception as e:
        logger.error(f"Redis delete error: {str(e)}")
        return False

def clear_cache():
    """
    Clear all keys in Redis cache with the application prefix.
    
    Returns:
        bool: True if successful, False otherwise
    """
    redis_client = get_redis_client()
    if not redis_client:
        logger.debug("Redis not configured, skipping cache clear")
        return False
        
    try:
        # Get prefix from config or use a default
        prefix = current_app.config.get('REDIS_KEY_PREFIX', 'app:')
        
        # Find all keys with prefix
        pattern = f"{prefix}*"
        keys = redis_client.keys(pattern)
        
        if keys:
            # Delete all matching keys
            return bool(redis_client.delete(*keys))
        return True
    except Exception as e:
        logger.error(f"Redis clear error: {str(e)}")
        return False

def cache_key_generator(*args, **kwargs):
    """
    Generate a consistent cache key from arguments.
    
    Args:
        *args: Positional arguments to include in key
        **kwargs: Keyword arguments to include in key
        
    Returns:
        str: Generated cache key
    """
    # Get prefix from config or use a default
    prefix = current_app.config.get('REDIS_KEY_PREFIX', 'app:')
    
    # Create key components
    components = [prefix]
    
    # Add positional args
    for arg in args:
        components.append(str(arg))
    
    # Add keyword args (sorted for consistency)
    for key in sorted(kwargs.keys()):
        components.append(f"{key}={kwargs[key]}")
    
    # Join with colons
    return ':'.join(components)
