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

def get_hash(hash_key, field=None):
    """
    Get values from a Redis hash.
    
    Args:
        hash_key (str): Hash key
        field (str, optional): Field to retrieve. If None, returns all fields. Defaults to None.
        
    Returns:
        dict or str: Hash values or specific field value, or None if not found
    """
    redis_client = get_redis_client()
    if not redis_client:
        logger.debug("Redis not configured, skipping hash get")
        return None
        
    try:
        if field is not None:
            # Get specific field
            value = redis_client.hget(hash_key, field)
            
            # Try to parse JSON if it looks like JSON
            if value and isinstance(value, str) and value.startswith('{') and value.endswith('}'):
                try:
                    return json.loads(value)
                except:
                    pass
            
            return value
        else:
            # Get all fields
            all_values = redis_client.hgetall(hash_key)
            
            # Try to parse JSON values
            for k, v in all_values.items():
                if v and isinstance(v, str) and v.startswith('{') and v.endswith('}'):
                    try:
                        all_values[k] = json.loads(v)
                    except:
                        pass
            
            return all_values
    except Exception as e:
        logger.error(f"Redis hash get error: {str(e)}")
        return None

def set_hash(hash_key, values, field=None, expiry=None):
    """
    Set values in a Redis hash.
    
    Args:
        hash_key (str): Hash key
        values (dict or str): Values to set. If field is None, must be a dict. If field is specified, can be any value.
        field (str, optional): Field to set. If None, values must be a dict. Defaults to None.
        expiry (int, optional): Expiry time in seconds. Defaults to None (no expiry).
        
    Returns:
        bool: True if successful, False otherwise
    """
    redis_client = get_redis_client()
    if not redis_client:
        logger.debug("Redis not configured, skipping hash set")
        return False
        
    try:
        # Handle different input formats
        if field is not None:
            # Set a single field
            field_value = values
            # Convert non-string values to JSON
            if not isinstance(field_value, str) and field_value is not None:
                field_value = json.dumps(field_value)
            
            result = redis_client.hset(hash_key, field, field_value)
        else:
            # Set multiple fields
            if not isinstance(values, dict):
                logger.error("Values must be a dict when field is not specified")
                return False
            
            # Convert non-string values to JSON
            serialized_values = {}
            for k, v in values.items():
                if not isinstance(v, str) and v is not None:
                    serialized_values[k] = json.dumps(v)
                else:
                    serialized_values[k] = v
            
            result = redis_client.hset(hash_key, mapping=serialized_values)
        
        # Set expiry if specified
        if expiry is not None and expiry > 0:
            redis_client.expire(hash_key, expiry)
        
        return result is not None and result >= 0
    except Exception as e:
        logger.error(f"Redis hash set error: {str(e)}")
        return False
