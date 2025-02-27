"""
Authentication and permission decorators for the payroll application.
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

def require_permission(permission_name: str, venue_id: Optional[str] = None):
    """
    Decorator to enforce that the current user has the required permission.
    
    Checks if the user has the specified permission in the given context.
    Returns a 403 Forbidden response if the user doesn't have the permission.
    
    Args:
        permission_name: Name of the permission to check
        venue_id: Optional venue ID for venue-specific permissions
        
    Usage:
        @app.route('/admin/reports')
        @require_permission('view_reports')
        def admin_reports():
            return "Reports page"
            
        @app.route('/venues/<venue_id>/manage')
        @require_permission('manage_venue', venue_id=lambda kwargs: kwargs.get('venue_id'))
        def manage_venue(venue_id):
            return f"Managing venue {venue_id}"
    """
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            try:
                user = g.user
                if not user:
                    return jsonify({
                        'success': False,
                        'message': 'Authentication required'
                    }), 401
                
                # Determine actual venue_id
                actual_venue_id = None
                if venue_id:
                    if callable(venue_id):
                        actual_venue_id = venue_id(kwargs)
                    else:
                        actual_venue_id = venue_id
                
                # Get business_id from user
                business_id = user.get('company_id')
                
                # Check permission using the permission manager
                if hasattr(current_app, 'permission_manager'):
                    permission_manager = current_app.permission_manager
                    
                    # Build context
                    context = {
                        'business_id': business_id,
                        'venue_id': actual_venue_id or user.get('venue_id')
                    }
                    
                    # Check permission
                    has_permission = permission_manager.check_permission(
                        user['payroll_id'],
                        permission_name,
                        context
                    )
                    
                    if has_permission:
                        return f(*args, **kwargs)
                else:
                    # Fallback to user's permissions array if no permission manager
                    permissions = user.get('permissions', [])
                    if permission_name in permissions:
                        return f(*args, **kwargs)
                
                # Log permission denial
                AuditLogger.log_event(
                    'permission_denied',
                    user.get('payroll_id', 'unknown'),
                    business_id or 'N/A',
                    f"Permission '{permission_name}' denied",
                    ip_address=request.remote_addr
                )
                
                # Handle API requests differently
                if request.is_json or request.headers.get('Accept') == 'application/json':
                    return jsonify({
                        'success': False,
                        'message': 'Permission denied'
                    }), 403
                else:
                    return redirect(url_for('auth.index'))
                
            except Exception as e:
                logger.error(f"Permission check error: {str(e)}")
                return jsonify({
                    'success': False,
                    'message': 'Error checking permissions'
                }), 500
        
        return decorated_function
    
    return decorator

def admin_required(f):
    """
    Decorator for routes that require admin privileges.
    Shorthand for @require_permission('admin').
    """
    @wraps(f)
    @require_permission('admin')
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    
    return decorated_function

def api_key_required(f):
    """
    Decorator for API routes that require an API key.
    Checks for a valid API key in request headers or query parameters.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({
                'success': False,
                'message': 'API key required'
            }), 401
        
        # Check API key in database
        api_key_doc = current_app.mongo.db.api_keys.find_one({
            'key': api_key,
            'status': 'active'
        })
        
        if not api_key_doc:
            return jsonify({
                'success': False,
                'message': 'Invalid API key'
            }), 401
        
        # Store API key context in g
        g.api_key = api_key_doc
        
        # Update last used timestamp
        current_app.mongo.db.api_keys.update_one(
            {'_id': api_key_doc['_id']},
            {'$set': {'last_used': datetime.utcnow()}}
        )
        
        return f(*args, **kwargs)
    
    return decorated_function
