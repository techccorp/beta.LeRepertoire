# ------------------------------------------------------------
# config/base_config.py
# ------------------------------------------------------------
import os
from dotenv import load_dotenv
import warnings
from datetime import timedelta

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration class for MyLocalFoodie application."""
    
    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
    MONGO_DBNAME = os.getenv('MONGO_DBNAME', 'MyCookBook')

    # MongoDB Collection Names
    COLLECTION_TAGS = os.getenv('COLLECTION_TAGS', 'tags')
    COLLECTION_GLOBAL_RECIPES = os.getenv('COLLECTION_GLOBAL_RECIPES', 'global_recipes')
    COLLECTION_USER_RECIPES = os.getenv('COLLECTION_USER_RECIPES', 'user_recipes')
    COLLECTION_USERS = os.getenv('COLLECTION_USERS', 'users')
    COLLECTION_PRODUCT_LIST = os.getenv('COLLECTION_PRODUCT_LIST', 'product_list')
    COLLECTION_ALLERGENS = os.getenv('COLLECTION_ALLERGENS', 'allergens')
    COLLECTION_USER_NOTES = os.getenv('COLLECTION_USER_NOTES', 'user_notes')
    COLLECTION_MEATSPACE = os.getenv('COLLECTION_MEATSPACE', 'meatspace')

    # Business Onboarding Collections
    COLLECTION_BUSINESSES = os.getenv('COLLECTION_BUSINESSES', 'business_entities')
    COLLECTION_BUSINESSES_VENUES = os.getenv('COLLECTION_BUSINESSES_VENUES', 'business_venues')
    COLLECTION_BUSINESS_USERS = os.getenv('COLLECTION_BUSINESS_USERS', 'business_users')
    COLLECTION_BUSINESS_CONFIG = os.getenv('COLLECTION_BUSINESS_CONFIG', 'business_config')   
    COLLECTION_BUSINESS_ROLES = os.getenv('COLLECTION_BUSINESS_ROLES', 'business_roles')
    COLLECTION_ROLE_IDS = os.getenv('COLLECTION_ROLE_IDS', 'role_ids')
    COLLECTION_EMPLOYMENT_ROLES = os.getenv('COLLECTION_EMPLOYMENT_ROLES', 'emplyment_roles')

    # Deprecation Notice for MONGO_SEARCH_DBNAME
    MONGO_SEARCH_DBNAME = os.getenv('MONGO_SEARCH_DBNAME')
    if MONGO_SEARCH_DBNAME:
        warnings.warn(
            "MONGO_SEARCH_DBNAME is deprecated. Use COLLECTION_PRODUCT_LIST instead.",
            DeprecationWarning
        )

    # Application Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'a_secure_random_key')
    HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    PORT = int(os.getenv('FLASK_PORT', 5000))
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    USE_SSL = os.getenv('USE_SSL', 'False').lower() == 'true'
    SSL_CONTEXT = (
        os.getenv('SSL_CERT_PATH', 'cert.pem'),
        os.getenv('SSL_KEY_PATH', 'key.pem')
    ) if USE_SSL else None

    # File Upload Configuration
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 10 * 1024 * 1024))  # 10MB default
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

    # Session Configuration
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = timedelta(days=int(os.getenv('SESSION_LIFETIME_DAYS', 7)))
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # CORS Configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    CORS_ALLOW_HEADERS = [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'Accept',
        'Origin',
        'Access-Control-Request-Method',
        'Access-Control-Request-Headers'
    ]

    # GridFS Configuration
    GRIDFS_BUCKET_NAME = os.getenv('GRIDFS_BUCKET_NAME', 'fs')

    # Cache Configuration
    CACHE_TYPE = os.getenv('CACHE_TYPE', 'simple')
    CACHE_DEFAULT_TIMEOUT = int(os.getenv('CACHE_DEFAULT_TIMEOUT', 300))

    # Rate Limiting
    RATELIMIT_DEFAULT = os.getenv('RATELIMIT_DEFAULT', '200 per day;50 per hour')
    RATELIMIT_STRATEGY = os.getenv('RATELIMIT_STRATEGY', 'fixed-window')
    RATELIMIT_STORAGE_URL = os.getenv('RATELIMIT_STORAGE_URL', 'memory://')

    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = os.getenv(
        'LOG_FORMAT',
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    def __init__(self):
        print("Loaded Configuration:")
        self._print_config()

    def _print_config(self):
        """Print configuration values, masking sensitive data."""
        for key in sorted(dir(self)):
            if key.isupper():
                value = getattr(self, key)
                if any(sensitive in key for sensitive in ['SECRET', 'KEY', 'PASSWORD', 'URI']):
                    print(f"- {key}: Set")
                else:
                    print(f"- {key}: {value}")
