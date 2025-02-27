# Create a new file: routes/auth/decorators.py
"""
Authentication decorators for Flask routes.
Provides reusable decorators for authentication and permission checks.
"""
from functools import wraps
from flask import g, current_app, request, redirect, url_for, jsonify, session
import logging
from typing import Optional, Dict, Any, Callable, Union

from utils.auth.auth_utils import extract_token_from_request, verify_token
from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

def login_required(f):
    """
    Decorator to protect routes requiring authentication.
    
    Checks for authenticated user in session or JWT token in Authorization header.
    Verifies that the user exists and is active, and makes the user data available 
    in Flask's global 'g' object.
    
    Usage:
        @app.route('/protected')
        @login_required
        def protected_route():
            # Access user data with g.user
            return f"Hello, {g.user['first_name']}"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check if user is in session
        if session.get('user') and session['user'].get('payroll_id'):
            user_id = session['user'].get('payroll_id')
            
            # Verify user exists and is active
            user = current_app.mongo.db.business_users.find_one({
                'payroll_id': user_id,
                'status': {'$ne': 'inactive'}
            })
            
            if user:
                g.user = user
                return f(*args, **kwargs)
        
        # If no session, check for token in Authorization header
        token = extract_token_from_request(request)
        if token:
            payload = verify_token(token)
            if payload:
                # Verify user exists and is active
                user = current_app.mongo.db.business_users.find_one({
                    'payroll_id': payload['payroll_id'],
                    'status': {'$ne': 'inactive'}
                })
                
                if user:
                    g.user = user
                    return f(*args, **kwargs)
        
        # Handle API requests differently from browser requests
        if request.is_json or request.headers.get('Accept') == 'application/json':
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        else:
            return redirect(url_for('auth.index'))
    
    return decorated_function

# Add other decorators from auth_routes.py here
