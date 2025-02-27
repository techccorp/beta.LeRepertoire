# ------------------------------------------------------------
# utils/auth/mfa.py
# ------------------------------------------------------------
"""
Multi-Factor Authentication implementation with TOTP and WebAuthn support.
"""
import base64
import hmac
import hashlib
import logging
import os
import time
from typing import Dict, Tuple, List, Optional, Any
import qrcode
import io
from flask import current_app, g, session
from pymongo import MongoClient

logger = logging.getLogger(__name__)

class MFAManager:
    """
    Multi-Factor Authentication Manager with TOTP and WebAuthn support.
    
    Features:
    - TOTP secret generation and validation
    - QR code generation for TOTP setup
    - WebAuthn registration and authentication
    - MFA state management (enabled/disabled, recovery codes)
    """
    
    def __init__(self, app=None):
        """
        Initialize the MFA Manager.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        self.db = None
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """
        Initialize with Flask app instance.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Get database connection
        @app.before_request
        def setup_mfa_manager():
            if not self.db:
                self.db = self._get_db()
        
        # Register functions with the app
        app.mfa_manager = self
    
    def generate_totp_secret(self) -> str:
        """
        Generate a new TOTP secret key.
        
        Returns:
            str: Base32-encoded TOTP secret
        """
        # Generate a random 20-byte key
        secret_bytes = os.urandom(20)
        
        # Encode to base32 for compatibility with authenticator apps
        secret = base64.b32encode(secret_bytes).decode('utf-8')
        
        return secret
    
    def generate_totp_qr_code(self, secret: str, user_data: Dict) -> bytes:
        """
        Generate a QR code for setting up TOTP in an authenticator app.
        
        Args:
            secret: TOTP secret key
            user_data: User data dictionary
            
        Returns:
            bytes: PNG image data of the QR code
        """
        # Create otpauth URI
        app_name = self.app.config.get('APP_NAME', 'Le Repertoire')
        user_identifier = user_data.get('work_email', user_data.get('payroll_id', 'user'))
        otpauth_uri = f"otpauth://totp/{app_name}:{user_identifier}?secret={secret}&issuer={app_name}"
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(otpauth_uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save to in-memory file
        img_io = io.BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        
        return img_io.read()
    
    def generate_recovery_codes(self, count: int = 10) -> List[str]:
        """
        Generate recovery codes for MFA backup.
        
        Args:
            count: Number of recovery codes to generate
            
        Returns:
            List[str]: List of recovery codes
        """
        recovery_codes = []
        for _ in range(count):
            # Generate a random 10-byte value
            code_bytes = os.urandom(10)
            
            # Convert to a readable string (5 groups of 4 characters)
            code = base64.b32encode(code_bytes).decode('utf-8')[:20]
            code = '-'.join([code[i:i+4] for i in range(0, 20, 4)])
            
            recovery_codes.append(code)
        
        return recovery_codes
    
    def setup_totp_mfa(self, user_id: str, payroll_id: str) -> Tuple[str, bytes, List[str]]:
        """
        Set up TOTP-based MFA for a user.
        
        Args:
            user_id: User's MongoDB ID
            payroll_id: User's payroll ID
            
        Returns:
            Tuple[str, bytes, List[str]]: (TOTP secret, QR code image, recovery codes)
        """
        try:
            # Get user data
            user = self.db.business_users.find_one({"payroll_id": payroll_id})
            
            if not user:
                raise ValueError(f"User with payroll ID {payroll_id} not found")
            
            # Generate TOTP secret
            secret = self.generate_totp_secret()
            
            # Generate QR code
            qr_code = self.generate_totp_qr_code(secret, user)
            
            # Generate recovery codes
            recovery_codes = self.generate_recovery_codes()
            
            # Create MFA record with pending status
            mfa_data = {
                "user_id": user_id,
                "payroll_id": payroll_id,
                "mfa_type": "totp",
                "totp_secret": secret,
                "recovery_codes": recovery_codes,
                "status": "pending",  # Will be changed to "active" after verification
                "created_at": time.time(),
                "last_used": None
            }
            
            # Store in database
            self.db.mfa.update_one(
                {"payroll_id": payroll_id},
                {"$set": mfa_data},
                upsert=True
            )
            
            return (secret, qr_code, recovery_codes)
            
        except Exception as e:
            logger.error(f"MFA setup error: {str(e)}")
            raise
    
    def verify_totp_code(self, payroll_id: str, code: str) -> bool:
        """
        Verify a TOTP code against a user's secret.
        
        Args:
            payroll_id: User's payroll ID
            code: TOTP code to verify
            
        Returns:
            bool: True if code is valid, False otherwise
        """
        try:
            # Get MFA data for user
            mfa_data = self.db.mfa.find_one({"payroll_id": payroll_id})
            
            if not mfa_data or mfa_data.get('mfa_type') != 'totp':
                logger.warning(f"TOTP verification failed: No TOTP setup for {payroll_id}")
                return False
            
            # Get TOTP secret
            secret = mfa_data.get('totp_secret')
            if not secret:
                logger.warning(f"TOTP verification failed: No secret for {payroll_id}")
                return False
            
            # Verify code
            if self._verify_totp(secret, code):
                # Update last used timestamp
                self.db.mfa.update_one(
                    {"payroll_id": payroll_id},
                    {"$set": {
                        "last_used": time.time(),
                        "status": "active"  # Ensure status is active if verification succeeds
                    }}
                )
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"TOTP verification error: {str(e)}")
            return False
    
    def verify_recovery_code(self, payroll_id: str, code: str) -> bool:
        """
        Verify a recovery code and mark it as used.
        
        Args:
            payroll_id: User's payroll ID
            code: Recovery code to verify
            
        Returns:
            bool: True if code is valid, False otherwise
        """
        try:
            # Get MFA data for user
            mfa_data = self.db.mfa.find_one({"payroll_id": payroll_id})
            
            if not mfa_data:
                logger.warning(f"Recovery code verification failed: No MFA setup for {payroll_id}")
                return False
            
            # Get recovery codes
            recovery_codes = mfa_data.get('recovery_codes', [])
            
            # Check if code is valid
            if code in recovery_codes:
                # Remove used code
                recovery_codes.remove(code)
                
                # Update database
                self.db.mfa.update_one(
                    {"payroll_id": payroll_id},
                    {"$set": {
                        "recovery_codes": recovery_codes,
                        "last_used": time.time()
                    }}
                )
                
                # Generate a new recovery code if running low
                if len(recovery_codes) < 3:
                    new_code = self.generate_recovery_codes(1)[0]
                    self.db.mfa.update_one(
                        {"payroll_id": payroll_id},
                        {"$push": {"recovery_codes": new_code}}
                    )
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Recovery code verification error: {str(e)}")
            return False
    
    def disable_mfa(self, payroll_id: str) -> bool:
        """
        Disable MFA for a user.
        
        Args:
            payroll_id: User's payroll ID
            
        Returns:
            bool: True if MFA was disabled, False otherwise
        """
        try:
            # Mark MFA as disabled
            result = self.db.mfa.update_one(
                {"payroll_id": payroll_id},
                {"$set": {"status": "disabled"}}
            )
            
            return result.modified_count > 0
            
        except Exception as e:
            logger.error(f"MFA disable error: {str(e)}")
            return False
    
    def get_mfa_status(self, payroll_id: str) -> Dict[str, Any]:
        """
        Get MFA status for a user.
        
        Args:
            payroll_id: User's payroll ID
            
        Returns:
            Dict: MFA status information
        """
        try:
            # Get MFA data for user
            mfa_data = self.db.mfa.find_one({"payroll_id": payroll_id})
            
            if not mfa_data:
                return {
                    "is_enabled": False,
                    "mfa_type": None,
                    "recovery_codes_remaining": 0
                }
            
            return {
                "is_enabled": mfa_data.get('status') == 'active',
                "mfa_type": mfa_data.get('mfa_type'),
                "recovery_codes_remaining": len(mfa_data.get('recovery_codes', [])),
                "last_used": mfa_data.get('last_used')
            }
            
        except Exception as e:
            logger.error(f"Error getting MFA status: {str(e)}")
            return {"is_enabled": False, "error": str(e)}
    
    def _verify_totp(self, secret: str, code: str, window: int = 1) -> bool:
        """
        Verify a TOTP code.
        
        Args:
            secret: TOTP secret key (base32 encoded)
            code: TOTP code to verify
            window: Time window to check (number of 30-second intervals)
            
        Returns:
            bool: True if code is valid, False otherwise
        """
        try:
            # Clean up code
            code = code.replace(' ', '').replace('-', '')
            
            # Convert code to integer
            try:
                code_int = int(code)
            except ValueError:
                return False
            
            # Get current timestamp
            now = int(time.time())
            
            # Check codes in the time window
            for i in range(-window, window + 1):
                # Calculate timestamp for this interval
                timestamp = now + i * 30
                
                # Calculate TOTP code for this timestamp
                expected_code = self._generate_totp(secret, timestamp)
                
                if code_int == expected_code:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"TOTP verification error: {str(e)}")
            return False
    
    def _generate_totp(self, secret: str, timestamp: int = None) -> int:
        """
        Generate a TOTP code.
        
        Args:
            secret: TOTP secret key (base32 encoded)
            timestamp: Timestamp to use (defaults to current time)
            
        Returns:
            int: TOTP code
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # Calculate time step
        time_step = int(timestamp // 30)
        
        # Decode secret
        secret_bytes = base64.b32decode(secret)
        
        # Convert time step to bytes (big-endian, 8 bytes)
        time_bytes = time_step.to_bytes(8, byteorder='big')
        
        # Generate HMAC-SHA1
        hmac_hash = hmac.new(secret_bytes, time_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0x0F
        binary = ((hmac_hash[offset] & 0x7F) << 24 |
                  (hmac_hash[offset + 1] & 0xFF) << 16 |
                  (hmac_hash[offset + 2] & 0xFF) << 8 |
                  (hmac_hash[offset + 3] & 0xFF))
        
        # Generate 6-digit code
        return binary % 1000000
    
    def _get_db(self):
        """Get MongoDB database connection."""
        if hasattr(current_app, 'mongo'):
            return current_app.mongo.db
        elif 'mongo' in g:
            return g.mongo.db
        else:
            # Create a new connection
            client = MongoClient(current_app.config['MONGO_URI'])
            db = client[current_app.config['MONGO_DBNAME']]
            return db


# Helper function to initialize MFA manager
def init_mfa_manager(app):
    """
    Initialize the MFA Manager with the application context.
    
    Args:
        app: Flask application instance
    
    Returns:
        MFAManager: Initialized MFA manager instance
    """
    mfa_manager = MFAManager(app)
    app.mfa_manager = mfa_manager
    return mfa_manager
