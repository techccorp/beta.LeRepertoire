# ------------------------------------------------------------
# routes/auth/mfa_routes.py
# ------------------------------------------------------------
from flask import Blueprint, request, jsonify, current_app, g, session, send_file
import io
import logging
from bson.objectid import ObjectId

# Import authentication decorator
from routes.auth.auth_routes import login_required

# Import AuditLogger for audit events
from utils.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

mfa = Blueprint('mfa', __name__, url_prefix='/auth/mfa')

@mfa.route('/setup', methods=['POST'])
@login_required
def setup_mfa():
    """
    Set up MFA for the current user.
    Returns TOTP secret and QR code URL.
    """
    try:
        # Check if user already has MFA enabled
        payroll_id = g.user.get('payroll_id')
        if not payroll_id:
            return jsonify({
                "success": False,
                "message": "User identification missing"
            }), 400
        
        # Get MFA manager
        if not hasattr(current_app, 'mfa_manager'):
            return jsonify({
                "success": False,
                "message": "MFA management not available"
            }), 501
        
        # Get MFA status
        mfa_status = current_app.mfa_manager.get_mfa_status(payroll_id)
        
        if mfa_status.get('is_enabled'):
            return jsonify({
                "success": False,
                "message": "MFA is already enabled for this account"
            }), 400
        
        # Set up TOTP MFA
        user_id = str(g.current_user.get('_id'))
        secret, qr_code, recovery_codes = current_app.mfa_manager.setup_totp_mfa(user_id, payroll_id)
        
        # Store secret temporarily in session for verification
        session['mfa_setup'] = {
            'secret': secret,
            'user_id': user_id,
            'payroll_id': payroll_id
        }
        
        # For security, we don't return the actual recovery codes until MFA is verified
        return jsonify({
            "success": True,
            "secret": secret,
            "qr_code_available": True,
            "recovery_codes_count": len(recovery_codes),
            "message": "MFA setup initiated. Please verify with a TOTP code to complete setup."
        })
        
    except Exception as e:
        logger.error(f"MFA setup error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"MFA setup failed: {str(e)}"
        }), 500

@mfa.route('/qr-code', methods=['GET'])
@login_required
def get_qr_code():
    """
    Get the QR code image for MFA setup.
    """
    try:
        # Check if MFA setup is in progress
        if 'mfa_setup' not in session:
            return jsonify({
                "success": False,
                "message": "No MFA setup in progress"
            }), 400
        
        # Get MFA manager
        if not hasattr(current_app, 'mfa_manager'):
            return jsonify({
                "success": False,
                "message": "MFA management not available"
            }), 501
        
        # Get user data
        payroll_id = g.user.get('payroll_id')
        if not payroll_id:
            return jsonify({
                "success": False,
                "message": "User identification missing"
            }), 400
        
        # Get QR code
        secret = session['mfa_setup']['secret']
        qr_code = current_app.mfa_manager.generate_totp_qr_code(secret, g.current_user)
        
        # Return QR code as image
        return send_file(
            io.BytesIO(qr_code),
            mimetype='image/png',
            as_attachment=False,
            download_name='mfa_qr_code.png'
        )
        
    except Exception as e:
        logger.error(f"QR code generation error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"QR code generation failed: {str(e)}"
        }), 500

@mfa.route('/verify', methods=['POST'])
@login_required
def verify_mfa_setup():
    """
    Verify MFA setup with a TOTP code.
    Completes the MFA setup process if verification is successful.
    """
    try:
        data = request.get_json()
        code = data.get('code')
        
        if not code:
            return jsonify({
                "success": False,
                "message": "TOTP code is required"
            }), 400
        
        # Check if MFA setup is in progress
        if 'mfa_setup' not in session:
            return jsonify({
                "success": False,
                "message": "No MFA setup in progress"
            }), 400
        
        # Get MFA manager
        if not hasattr(current_app, 'mfa_manager'):
            return jsonify({
                "success": False,
                "message": "MFA management not available"
            }), 501
        
        # Get setup data
        setup_data = session['mfa_setup']
        secret = setup_data.get('secret')
        payroll_id = setup_data.get('payroll_id')
        
        # Verify code
        if current_app.mfa_manager._verify_totp(secret, code):
            # Update MFA status to active
            db = current_app.mongo.db
            db.mfa.update_one(
                {"payroll_id": payroll_id},
                {"$set": {"status": "active"}}
            )
            
            # Get recovery codes
            mfa_data = db.mfa.find_one({"payroll_id": payroll_id})
            recovery_codes = mfa_data.get('recovery_codes', [])
            
            # Log MFA activation
            AuditLogger.log_event(
                'mfa_activated',
                payroll_id,
                g.current_user.get('company_id', 'N/A'),
                'MFA activated successfully',
                ip_address=request.remote_addr
            )
            
            # Clear setup data from session
            session.pop('mfa_setup', None)
            
            return jsonify({
                "success": True,
                "message": "MFA activated successfully",
                "recovery_codes": recovery_codes
            })
        else:
            return jsonify({
                "success": False,
                "message": "Invalid TOTP code. Please try again."
            }), 400
            
    except Exception as e:
        logger.error(f"MFA verification error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"MFA verification failed: {str(e)}"
        }), 500

@mfa.route('/authenticate', methods=['POST'])
def authenticate_mfa():
    """
    Authenticate with MFA after password validation.
    Intended to be called from login flow if MFA is enabled.
    """
    try:
        data = request.get_json()
        payroll_id = data.get('payroll_id')
        code = data.get('code')
        use_recovery_code = data.get('use_recovery_code', False)
        
        if not payroll_id or not code:
            return jsonify({
                "success": False,
                "message": "Payroll ID and code are required"
            }), 400
        
        # Get MFA manager
        if not hasattr(current_app, 'mfa_manager'):
            return jsonify({
                "success": False,
                "message": "MFA management not available"
            }), 501
        
        # Check MFA status
        mfa_status = current_app.mfa_manager.get_mfa_status(payroll_id)
        
        if not mfa_status.get('is_enabled'):
            return jsonify({
                "success": False,
                "message": "MFA is not enabled for this account"
            }), 400
        
        # Verify code
        if use_recovery_code:
            is_valid = current_app.mfa_manager.verify_recovery_code(payroll_id, code)
            method = 'recovery code'
        else:
            is_valid = current_app.mfa_manager.verify_totp_code(payroll_id, code)
            method = 'TOTP'
        
        if is_valid:
            # Set MFA authenticated flag in session
            session['mfa_authenticated'] = True
            session['mfa_auth_time'] = time.time()
            
            # Log MFA authentication
            AuditLogger.log_event(
                'mfa_authenticated',
                payroll_id,
                'N/A',  # We don't have company_id at this point
                f'MFA authenticated using {method}',
                ip_address=request.remote_addr
            )
            
            return jsonify({
                "success": True,
                "message": "MFA authentication successful"
            })
        else:
            # Log failed attempt
            AuditLogger.log_event(
                'mfa_authentication_failed',
                payroll_id,
                'N/A',
                f'MFA authentication failed using {method}',
                ip_address=request.remote_addr
            )
            
            return jsonify({
                "success": False,
                "message": f"Invalid {method}. Please try again."
            }), 400
            
    except Exception as e:
        logger.error(f"MFA authentication error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"MFA authentication failed: {str(e)}"
        }), 500

@mfa.route('/disable', methods=['POST'])
@login_required
def disable_mfa():
    """
    Disable MFA for the current user.
    """
    try:
        data = request.get_json()
        password = data.get('password')
        
        if not password:
            return jsonify({
                "success": False,
                "message": "Password is required to disable MFA"
            }), 400
        
        # Get MFA manager
        if not hasattr(current_app, 'mfa_manager'):
            return jsonify({
                "success": False,
                "message": "MFA management not available"
            }), 501
        
        # Verify password
        from utils.auth.auth_utils import check_password
        if not check_password(g.current_user.get('password', ''), password):
            return jsonify({
                "success": False,
                "message": "Invalid password"
            }), 400
        
        # Disable MFA
        payroll_id = g.user.get('payroll_id')
        if current_app.mfa_manager.disable_mfa(payroll_id):
            # Log MFA deactivation
            AuditLogger.log_event(
                'mfa_deactivated',
                payroll_id,
                g.current_user.get('company_id', 'N/A'),
                'MFA deactivated',
                ip_address=request.remote_addr
            )
            
            return jsonify({
                "success": True,
                "message": "MFA has been disabled"
            })
        else:
            return jsonify({
                "success": False,
                "message": "Failed to disable MFA"
            }), 500
            
    except Exception as e:
        logger.error(f"MFA disable error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Failed to disable MFA: {str(e)}"
        }), 500

@mfa.route('/status', methods=['GET'])
@login_required
def mfa_status():
    """
    Get MFA status for the current user.
    """
    try:
        # Get MFA manager
        if not hasattr(current_app, 'mfa_manager'):
            return jsonify({
                "success": False,
                "message": "MFA management not available"
            }), 501
        
        # Get MFA status
        payroll_id = g.user.get('payroll_id')
        status = current_app.mfa_manager.get_mfa_status(payroll_id)
        
        return jsonify({
            "success": True,
            "mfa_status": status
        })
        
    except Exception as e:
        logger.error(f"MFA status error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Failed to get MFA status: {str(e)}"
        }), 500

@mfa.route('/generate-recovery-codes', methods=['POST'])
@login_required
def generate_recovery_codes():
    """
    Generate new recovery codes for the current user.
    """
    try:
        data = request.get_json()
        password = data.get('password')
        
        if not password:
            return jsonify({
                "success": False,
                "message": "Password is required to generate new recovery codes"
            }), 400
        
        # Get MFA manager
        if not hasattr(current_app, 'mfa_manager'):
            return jsonify({
                "success": False,
                "message": "MFA management not available"
            }), 501
        
        # Verify password
        from utils.auth.auth_utils import check_password
        if not check_password(g.current_user.get('password', ''), password):
            return jsonify({
                "success": False,
                "message": "Invalid password"
            }), 400
        
        # Generate new recovery codes
        payroll_id = g.user.get('payroll_id')
        recovery_codes = current_app.mfa_manager.generate_recovery_codes()
        
        # Update database
        db = current_app.mongo.db
        db.mfa.update_one(
            {"payroll_id": payroll_id},
            {"$set": {"recovery_codes": recovery_codes}}
        )
        
        # Log recovery codes regeneration
        AuditLogger.log_event(
            'mfa_recovery_codes_regenerated',
            payroll_id,
            g.current_user.get('company_id', 'N/A'),
            'MFA recovery codes regenerated',
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "success": True,
            "message": "New recovery codes generated",
            "recovery_codes": recovery_codes
        })
        
    except Exception as e:
        logger.error(f"Recovery codes generation error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Failed to generate recovery codes: {str(e)}"
        }), 500

# Ensure import in __init__.py
def register_mfa_routes(app):
    app.register_blueprint(mfa)
