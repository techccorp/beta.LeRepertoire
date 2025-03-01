# ------------------------------------------------------------
# config/redis_config.py
# ------------------------------------------------------------
"""
Redis configuration module.
Provides centralized Redis connection settings for the application.
"""
import os
import logging

logger = logging.getLogger(__name__)

class RedisConfig:
    """Redis connection configuration."""
    
    # Connection settings
    REDIS_HOST = os.environ.get('REDIS_HOST', 'redis-19392.c337.australia-southeast1-1.gce.redns.redis-cloud.com')
    REDIS_PORT = int(os.environ.get('REDIS_PORT', '19392'))
    REDIS_USERNAME = os.environ.get('REDIS_USERNAME', 'default')
    REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', 'zxNVxzSA21RRZk3dvSdK3swfE67quFMi')
    REDIS_DB = int(os.environ.get('REDIS_DB', '0'))
    REDIS_DECODE_RESPONSES = os.environ.get('REDIS_DECODE_RESPONSES', 'True').lower() == 'true'
    
    # Constructed URL
    REDIS_URL = f"redis://{REDIS_USERNAME}:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
    
    # Cache settings
    REDIS_KEY_PREFIX = os.environ.get('REDIS_KEY_PREFIX', 'lerepertoire:')
    REDIS_DEFAULT_EXPIRY = int(os.environ.get('REDIS_DEFAULT_EXPIRY', '3600'))  # 1 hour
    REDIS_LONG_EXPIRY = int(os.environ.get('REDIS_LONG_EXPIRY', '86400'))  # 24 hours
    
    # Connection pool settings
    REDIS_MAX_CONNECTIONS = int(os.environ.get('REDIS_MAX_CONNECTIONS', '10'))
    REDIS_SOCKET_TIMEOUT = int(os.environ.get('REDIS_SOCKET_TIMEOUT', '5'))
    REDIS_SOCKET_CONNECT_TIMEOUT = int(os.environ.get('REDIS_SOCKET_CONNECT_TIMEOUT', '5'))
    
    @classmethod
    def get_redis_url(cls):
        """
        Get Redis URL from configuration.
        
        Returns:
            str: Redis URL for connection
        """
        return cls.REDIS_URL

    @classmethod
    def get_connection_params(cls):
        """
        Get Redis connection parameters.
        
        Returns:
            dict: Connection parameters for Redis client
        """
        return {
            'host': cls.REDIS_HOST,
            'port': cls.REDIS_PORT,
            'username': cls.REDIS_USERNAME,
            'password': cls.REDIS_PASSWORD,
            'db': cls.REDIS_DB,
            'decode_responses': cls.REDIS_DECODE_RESPONSES,
            'socket_timeout': cls.REDIS_SOCKET_TIMEOUT,
            'socket_connect_timeout': cls.REDIS_SOCKET_CONNECT_TIMEOUT
        }
    
    @classmethod
    def validate_config(cls):
        """
        Validate Redis configuration.
        
        Raises:
            RedisConfigError: If configuration is invalid
        """
        errors = []
        
        if not cls.REDIS_HOST:
            errors.append("REDIS_HOST is not configured")
            
        if not cls.REDIS_PORT:
            errors.append("REDIS_PORT is not configured")
            
        if not cls.REDIS_PASSWORD:
            errors.append("REDIS_PASSWORD is not configured")
            
        if errors:
            raise RedisConfigError("; ".join(errors))
            
        return True

class RedisConfigError(Exception):
    """Exception raised for Redis configuration errors."""
    pass
