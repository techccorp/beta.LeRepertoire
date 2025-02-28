
# ------------------------------------------------#
#          config/google_oauth_config.py          #
# ------------------------------------------------#

from os import environ

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

class GoogleOAuthConfigError(Exception):
    """Custom exception for Google OAuth configuration errors."""
    pass
