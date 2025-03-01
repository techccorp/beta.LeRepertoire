"""
Configuration utilities for loading, saving, and managing application configuration.
Provides centralized functions for config operations across different storage backends.
"""
import json
import logging
import os
from datetime import datetime
from flask import current_app

logger = logging.getLogger(__name__)

# Try to import yaml, but don't fail if it's not available
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger.warning("PyYAML not installed. YAML configuration features will be disabled.")

def load_config(config_path=None, config_type=None):
    """
    Load configuration from a file or environment variables.
    
    Args:
        config_path (str, optional): Path to configuration file. Defaults to None.
        config_type (str, optional): Type of configuration ('json', 'yaml', 'env'). Defaults to None.
        
    Returns:
        dict: Configuration data dictionary
    """
    # Default configuration type based on file extension if not specified
    if config_path and not config_type:
        _, ext = os.path.splitext(config_path)
        if ext.lower() in ['.json']:
            config_type = 'json'
        elif ext.lower() in ['.yaml', '.yml']:
            if YAML_AVAILABLE:
                config_type = 'yaml'
            else:
                logger.warning(f"YAML support not available. Falling back to JSON for file: {config_path}")
                config_type = 'json'
        else:
            config_type = 'env'
    
    # Handle different configuration types
    if config_type == 'json':
        return _load_json_config(config_path)
    elif config_type == 'yaml':
        if YAML_AVAILABLE:
            return _load_yaml_config(config_path)
        else:
            logger.warning("YAML support not available. Falling back to environment variables.")
            return _load_env_config()
    else:
        # Default to environment variables
        return _load_env_config()

def _load_json_config(config_path):
    """
    Load configuration from a JSON file.
    
    Args:
        config_path (str): Path to JSON configuration file
        
    Returns:
        dict: Configuration data
    """
    try:
        if not os.path.exists(config_path):
            logger.warning(f"Configuration file not found: {config_path}")
            return {}
            
        with open(config_path, 'r') as config_file:
            config_data = json.load(config_file)
            
        logger.info(f"Loaded JSON configuration from {config_path}")
        return config_data
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file {config_path}: {str(e)}")
        return {}
    except Exception as e:
        logger.error(f"Error loading JSON configuration: {str(e)}")
        return {}

def _load_yaml_config(config_path):
    """
    Load configuration from a YAML file.
    
    Args:
        config_path (str): Path to YAML configuration file
        
    Returns:
        dict: Configuration data
    """
    if not YAML_AVAILABLE:
        logger.error("PyYAML not installed. Cannot load YAML configuration.")
        return {}
        
    try:
        if not os.path.exists(config_path):
            logger.warning(f"Configuration file not found: {config_path}")
            return {}
            
        with open(config_path, 'r') as config_file:
            config_data = yaml.safe_load(config_file)
            
        logger.info(f"Loaded YAML configuration from {config_path}")
        return config_data
    except yaml.YAMLError as e:
        logger.error(f"Invalid YAML in configuration file {config_path}: {str(e)}")
        return {}
    except Exception as e:
        logger.error(f"Error loading YAML configuration: {str(e)}")
        return {}

def _load_env_config(prefix=None):
    """
    Load configuration from environment variables.
    
    Args:
        prefix (str, optional): Prefix for environment variables to include. Defaults to None.
        
    Returns:
        dict: Configuration data
    """
    try:
        config_data = {}
        
        # Process environment variables
        for key, value in os.environ.items():
            # Apply prefix filter if specified
            if prefix and not key.startswith(prefix):
                continue
                
            # Remove prefix if needed
            if prefix and key.startswith(prefix):
                config_key = key[len(prefix):]
            else:
                config_key = key
                
            # Convert values to appropriate types
            if value.lower() == 'true':
                value = True
            elif value.lower() == 'false':
                value = False
            elif value.isdigit():
                value = int(value)
            elif value.replace('.', '', 1).isdigit() and value.count('.') == 1:
                value = float(value)
                
            # Add to config dictionary
            config_data[config_key] = value
            
        logger.info(f"Loaded {len(config_data)} settings from environment variables")
        return config_data
    except Exception as e:
        logger.error(f"Error loading configuration from environment: {str(e)}")
        return {}

def save_config(config_data, config_path, config_type=None):
    """
    Save configuration to a file.
    
    Args:
        config_data (dict): Configuration data
        config_path (str): Path to save configuration file
        config_type (str, optional): Type of configuration ('json', 'yaml'). Defaults to None.
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Default configuration type based on file extension if not specified
    if not config_type:
        _, ext = os.path.splitext(config_path)
        if ext.lower() in ['.json']:
            config_type = 'json'
        elif ext.lower() in ['.yaml', '.yml']:
            if YAML_AVAILABLE:
                config_type = 'yaml'
            else:
                logger.warning("YAML support not available. Saving as JSON instead.")
                config_type = 'json'
        else:
            config_type = 'json'  # Default to JSON
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
    
    # Handle different configuration types
    try:
        if config_type == 'yaml':
            if not YAML_AVAILABLE:
                logger.error("PyYAML not installed. Cannot save YAML configuration.")
                return False
                
            with open(config_path, 'w') as config_file:
                yaml.dump(config_data, config_file, default_flow_style=False)
        else:
            # Default to JSON
            with open(config_path, 'w') as config_file:
                json.dump(config_data, config_file, indent=2)
                
        logger.info(f"Saved configuration to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving configuration: {str(e)}")
        return False

def validate_config(config_data, required_fields=None, validators=None):
    """
    Validate configuration data.
    
    Args:
        config_data (dict): Configuration data to validate
        required_fields (list, optional): List of required fields. Defaults to None.
        validators (dict, optional): Custom validation functions. Defaults to None.
        
    Returns:
        tuple: (is_valid, error_messages)
    """
    errors = []
    
    # Check for required fields
    if required_fields:
        for field in required_fields:
            if field not in config_data:
                errors.append(f"Missing required field: {field}")
    
    # Apply custom validators
    if validators and isinstance(validators, dict):
        for field, validator in validators.items():
            if field in config_data:
                try:
                    result = validator(config_data[field])
                    if result is not True and result is not None:
                        errors.append(f"Invalid value for {field}: {result}")
                except Exception as e:
                    errors.append(f"Validation error for {field}: {str(e)}")
    
    # Return validation result
    return len(errors) == 0, errors

def get_config_value(key, default=None):
    """
    Get a configuration value from the application config.
    
    Args:
        key (str): Configuration key
        default (any, optional): Default value if key not found. Defaults to None.
        
    Returns:
        any: Configuration value or default
    """
    try:
        # Try to get from Flask app config
        if hasattr(current_app, 'config'):
            return current_app.config.get(key, default)
            
        # If no Flask app context, try environment variables
        env_value = os.environ.get(key)
        if env_value is not None:
            # Convert values to appropriate types
            if env_value.lower() == 'true':
                return True
            elif env_value.lower() == 'false':
                return False
            elif env_value.isdigit():
                return int(env_value)
            elif env_value.replace('.', '', 1).isdigit() and env_value.count('.') == 1:
                return float(env_value)
            return env_value
            
        return default
    except Exception as e:
        logger.error(f"Error getting config value for {key}: {str(e)}")
        return default

def set_config_value(key, value, persist=False):
    """
    Set a configuration value in the application config.
    
    Args:
        key (str): Configuration key
        value (any): Configuration value
        persist (bool, optional): Persist to configuration file. Defaults to False.
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Set in Flask app config
        if hasattr(current_app, 'config'):
            current_app.config[key] = value
            
            # Persist to file if requested
            if persist and hasattr(current_app, 'config_file'):
                config_file = current_app.config_file
                config_data = load_config(config_file)
                config_data[key] = value
                return save_config(config_data, config_file)
                
            return True
            
        # If no Flask app context, we can't persist
        if persist:
            logger.warning("Cannot persist config without Flask app context")
            return False
            
        # Set as environment variable (not persistent)
        os.environ[key] = str(value)
        return True
    except Exception as e:
        logger.error(f"Error setting config value for {key}: {str(e)}")
        return False

def get_mongodb_config():
    """
    Get MongoDB configuration from the application config.
    
    Returns:
        dict: MongoDB configuration
    """
    try:
        config = {
            'uri': get_config_value('MONGO_URI', 'mongodb://localhost:27017/'),
            'db_name': get_config_value('MONGO_DBNAME', 'MyCookBook'),
            'connect_timeout': get_config_value('MONGO_CONNECT_TIMEOUT', 5000),
            'max_pool_size': get_config_value('MONGO_MAX_POOL_SIZE', 100),
            'server_selection_timeout': get_config_value('MONGO_SERVER_SELECTION_TIMEOUT', 10000)
        }
        return config
    except Exception as e:
        logger.error(f"Error getting MongoDB config: {str(e)}")
        return {
            'uri': 'mongodb://localhost:27017/',
            'db_name': 'MyCookBook'
        }

def get_redis_config():
    """
    Get Redis configuration from the application config.
    
    Returns:
        dict: Redis configuration
    """
    try:
        config = {
            'host': get_config_value('REDIS_HOST', 'localhost'),
            'port': get_config_value('REDIS_PORT', 6379),
            'username': get_config_value('REDIS_USERNAME', None),
            'password': get_config_value('REDIS_PASSWORD', None),
            'db': get_config_value('REDIS_DB', 0),
            'decode_responses': get_config_value('REDIS_DECODE_RESPONSES', True),
            'key_prefix': get_config_value('REDIS_KEY_PREFIX', 'app:'),
            'default_expiry': get_config_value('REDIS_DEFAULT_EXPIRY', 3600)
        }
        return config
    except Exception as e:
        logger.error(f"Error getting Redis config: {str(e)}")
        return {
            'host': 'localhost',
            'port': 6379,
            'db': 0
        }

def get_application_config():
    """
    Get essential application configuration.
    
    Returns:
        dict: Application configuration
    """
    try:
        config = {
            'secret_key': get_config_value('SECRET_KEY', 'development_key'),
            'debug': get_config_value('DEBUG', False),
            'host': get_config_value('HOST', '0.0.0.0'),
            'port': get_config_value('PORT', 5000),
            'upload_folder': get_config_value('UPLOAD_FOLDER', 'uploads'),
            'allowed_extensions': get_config_value('ALLOWED_EXTENSIONS', {'png', 'jpg', 'jpeg'}),
            'max_file_size': get_config_value('MAX_FILE_SIZE', 10 * 1024 * 1024)
        }
        return config
    except Exception as e:
        logger.error(f"Error getting application config: {str(e)}")
        return {
            'debug': False,
            'host': '0.0.0.0',
            'port': 5000
        }
