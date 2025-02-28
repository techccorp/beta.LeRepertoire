# ------------------------------------------------#
#          config/google_oauth_config.py          #
# ------------------------------------------------#
from os import environ

class GoogleOAuthConfigError(Exception):
    """Custom exception for Google OAuth configuration errors."""
    pass

class GoogleOAuthConfig:
    # OAuth 2.0 Client credentials
    GOOGLE_CLIENT_ID = environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = environ.get('GOOGLE_CLIENT_SECRET')
    
    # OAuth 2.0 Scopes
    GOOGLE_SCOPES = [
        'openid',
        'email',
        'profile',
        'https://www.googleapis.com/auth/calendar',
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/tasks'
    ]
    
    # OAuth endpoints
    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
    GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
    GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
    
    # Redirect URI
    GOOGLE_REDIRECT_URI = environ.get('GOOGLE_REDIRECT_URI', 'http://localhost:5000/auth/google/callback')
    
    @classmethod
    def validate_config(cls):
        """Validate that all required configuration values are present."""
        if not cls.GOOGLE_CLIENT_ID:
            raise GoogleOAuthConfigError("GOOGLE_CLIENT_ID environment variable is not set")
        if not cls.GOOGLE_CLIENT_SECRET:
            raise GoogleOAuthConfigError("GOOGLE_CLIENT_SECRET environment variable is not set")
        return True
    
    @classmethod
    def get_oauth_config(cls):
        """Return a dictionary with all OAuth configuration."""
        cls.validate_config()
        return {
            'client_id': cls.GOOGLE_CLIENT_ID,
            'client_secret': cls.GOOGLE_CLIENT_SECRET,
            'scopes': cls.GOOGLE_SCOPES,
            'discovery_url': cls.GOOGLE_DISCOVERY_URL,
            'token_uri': cls.GOOGLE_TOKEN_URI,
            'auth_uri': cls.GOOGLE_AUTH_URI,
            'redirect_uri': cls.GOOGLE_REDIRECT_URI
        }
