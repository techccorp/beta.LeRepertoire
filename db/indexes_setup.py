# ------------------------------------------------------------
# db/indexes_setup.py
# ------------------------------------------------------------
"""
Database index setup script for MongoDB collections.
Creates optimized indexes for authentication and permission collections.
"""
import logging
from pymongo import ASCENDING, DESCENDING, TEXT

logger = logging.getLogger(__name__)

def setup_authentication_indexes(db):
    """
    Set up indexes for authentication-related collections.
    
    Args:
        db: MongoDB database instance
    """
    try:
        # User indexes
        logger.info("Setting up indexes for business_users collection...")
        db.business_users.create_index([("payroll_id", ASCENDING)], unique=True)
        db.business_users.create_index([("work_email", ASCENDING)])
        db.business_users.create_index([("linking_id", ASCENDING)])
        db.business_users.create_index([("company_id", ASCENDING), ("status", ASCENDING)])
        db.business_users.create_index([("venue_id", ASCENDING), ("status", ASCENDING)])
        db.business_users.create_index([("work_area_id", ASCENDING), ("status", ASCENDING)])
        db.business_users.create_index([("role", ASCENDING)])
        db.business_users.create_index([("last_login", DESCENDING)])
        
        # Session indexes
        logger.info("Setting up indexes for active_sessions collection...")
        db.active_sessions.create_index([("session_id", ASCENDING)], unique=True)
        db.active_sessions.create_index([("user_id", ASCENDING)])
        db.active_sessions.create_index([("last_activity", ASCENDING)])
        db.active_sessions.create_index([("created_at", ASCENDING)])
        db.active_sessions.create_index([("expires_at", ASCENDING)])
        
        # Refresh token indexes
        logger.info("Setting up indexes for refresh_tokens collection...")
        db.refresh_tokens.create_index([("token", ASCENDING)], unique=True)
        db.refresh_tokens.create_index([("user_id", ASCENDING)])
        db.refresh_tokens.create_index([("expires_at", ASCENDING)])
        
        # Revoked token indexes
        logger.info("Setting up indexes for revoked_tokens collection...")
        db.revoked_tokens.create_index([("jti", ASCENDING)], unique=True)
        db.revoked_tokens.create_index([("expires_at", ASCENDING)])
        db.revoked_tokens.create_index([("revoked_at", ASCENDING)])
        
        # MFA indexes
        logger.info("Setting up indexes for mfa collection...")
        db.mfa.create_index([("payroll_id", ASCENDING)], unique=True)
        db.mfa.create_index([("user_id", ASCENDING)])
        db.mfa.create_index([("status", ASCENDING)])
        
        # Password reset indexes
        logger.info("Setting up indexes for password_reset_tokens collection...")
        db.password_reset_tokens.create_index([("token", ASCENDING)], unique=True)
        db.password_reset_tokens.create_index([("user_id", ASCENDING)])
        db.password_reset_tokens.create_index([("expires_at", ASCENDING)])
        db.password_reset_tokens.create_index([("used", ASCENDING)])
        
        logger.info("Authentication indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error setting up authentication indexes: {str(e)}")
        raise

def setup_permission_indexes(db):
    """
    Set up indexes for permission-related collections.
    
    Args:
        db: MongoDB database instance
    """
    try:
        # Role indexes
        logger.info("Setting up indexes for business_roles collection...")
        db.business_roles.create_index([("role_name", ASCENDING)], unique=True)
        
        # Role assignment indexes
        logger.info("Setting up indexes for role_assignments collection...")
        db.role_assignments.create_index([("user_id", ASCENDING), ("context.business_id", ASCENDING)], unique=True)
        db.role_assignments.create_index([("role_id", ASCENDING)])
        db.role_assignments.create_index([("context.business_id", ASCENDING)])
        db.role_assignments.create_index([("context.venue_id", ASCENDING)])
        db.role_assignments.create_index([("context.work_area_id", ASCENDING)])
        db.role_assignments.create_index([("status", ASCENDING)])
        
        # Permission cache indexes
        logger.info("Setting up indexes for permission_cache collection...")
        db.permission_cache.create_index(
            [("user_id", ASCENDING), ("permission", ASCENDING), ("context_hash", ASCENDING)],
            unique=True
        )
        db.permission_cache.create_index([("expires_at", ASCENDING)])
        
        logger.info("Permission indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error setting up permission indexes: {str(e)}")
        raise

def setup_business_indexes(db):
    """
    Set up indexes for business-related collections.
    
    Args:
        db: MongoDB database instance
    """
    try:
        # Business entities indexes
        logger.info("Setting up indexes for business_entities collection...")
        db.business_entities.create_index([("company_id", ASCENDING)], unique=True)
        db.business_entities.create_index([("company_name", TEXT)])
        db.business_entities.create_index([("venues.venue_id", ASCENDING)])
        
        # Business venues indexes
        logger.info("Setting up indexes for business_venues collection...")
        db.business_venues.create_index([("venue_id", ASCENDING)], unique=True)
        db.business_venues.create_index([("company_id", ASCENDING)])
        db.business_venues.create_index([("venue_name", TEXT)])
        db.business_venues.create_index([("workareas.work_area_id", ASCENDING)])
        
        # Business users indexes (additional indexes)
        logger.info("Setting up additional indexes for business_users collection...")
        db.business_users.create_index([("work_email", TEXT)])
        db.business_users.create_index([("first_name", TEXT), ("last_name", TEXT), ("preferred_name", TEXT)])
        
        logger.info("Business indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error setting up business indexes: {str(e)}")
        raise

def setup_audit_indexes(db):
    """
    Set up indexes for audit logging.
    
    Args:
        db: MongoDB database instance
    """
    try:
        # Audit log indexes
        logger.info("Setting up indexes for audit_logs collection...")
        db.audit_logs.create_index([("event_type", ASCENDING)])
        db.audit_logs.create_index([("user_id", ASCENDING)])
        db.audit_logs.create_index([("business_id", ASCENDING)])
        db.audit_logs.create_index([("timestamp", DESCENDING)])
        db.audit_logs.create_index([("ip_address", ASCENDING)])
        
        logger.info("Audit indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error setting up audit indexes: {str(e)}")
        raise

def setup_all_indexes(db):
    """
    Set up all indexes for the application.
    
    Args:
        db: MongoDB database instance
    """
    try:
        setup_authentication_indexes(db)
        setup_permission_indexes(db)
        setup_business_indexes(db)
        setup_audit_indexes(db)
        
        logger.info("All indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error setting up indexes: {str(e)}")
        raise

def init_indexes(app):
    """
    Initialize MongoDB indexes with the application context.
    
    Args:
        app: Flask application instance
    """
    try:
        with app.app_context():
            db = app.mongo.db
            setup_all_indexes(db)
            
    except Exception as e:
        logger.error(f"Error initializing indexes: {str(e)}")
        raise
