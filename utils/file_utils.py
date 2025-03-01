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

def handle_index_conflict(collection, index_specs, **kwargs):
    """
    Handle potential index conflicts by dropping existing indexes and recreating them.
    
    Args:
        collection: MongoDB collection
        index_specs: List of tuples defining index fields
        **kwargs: Additional arguments for create_index
    
    Returns:
        Result of create_index operation or None if skipped
    """
    try:
        # CRITICAL FIX: Never attempt to create unique index on _id field
        if len(index_specs) == 1 and index_specs[0][0] == "_id":
            logger.warning(f"Skipping index creation on _id field for {collection.name}")
            return None
            
        # Check any of the fields is _id
        if any(field[0] == '_id' for field in index_specs):
            logger.warning(f"Skipping index creation containing _id field for {collection.name}")
            return None
            
        # For the specific idx_linking_id case, use that name if we're dealing with linking_id
        if collection.name == "business_users" and len(index_specs) == 1 and index_specs[0][0] == "linking_id":
            # Use the existing name to avoid conflicts
            kwargs["name"] = "idx_linking_id"
            logger.info(f"Using existing index name 'idx_linking_id' for linking_id field in {collection.name}")
            return collection.create_index(index_specs, **kwargs)
            
        # Try to create the index normally
        return collection.create_index(index_specs, **kwargs)
    except Exception as e:
        # Check if it's an index conflict
        if "Index already exists with a different name" in str(e):
            # Get existing indexes
            existing_indexes = collection.index_information()
            
            # Find the conflicting index by comparing key patterns
            target_fields = [f for f, _ in index_specs]
            for idx_name, idx_info in existing_indexes.items():
                if idx_name == '_id_':  # Skip the default _id index
                    continue
                    
                # Compare field names (ignoring sort direction)
                idx_fields = [f for f, _ in idx_info.get('key', [])]
                if set(idx_fields) == set(target_fields):
                    # Found the conflicting index - drop it
                    logger.info(f"Dropping conflicting index '{idx_name}' in {collection.name}")
                    collection.drop_index(idx_name)
                    break
            
            # Now recreate the index
            logger.info(f"Recreating index in {collection.name}")
            return collection.create_index(index_specs, **kwargs)
        elif "The field 'unique' is not valid for an *id index specification" in str(e):
            # This is the specific error we're fixing
            logger.warning(f"Cannot create unique index on _id field for {collection.name}")
            return None
        else:
            # If it's not an index conflict, re-raise the exception
            logger.error(f"Index creation error: {str(e)}")
            # Don't raise, just return None to continue with other indexes
            return None

def setup_authentication_indexes(db):
    """
    Set up indexes for authentication-related collections.
    Added validation to check collection existence and prevent _id index creation.
    
    Args:
        db: MongoDB database instance
    """
    try:
        # Validate collection exists before indexing
        if 'business_users' not in db.list_collection_names():
            logger.warning("business_users collection does not exist, skipping indexes")
            return
            
        # User indexes - added existence check for payroll_id field
        logger.info("Setting up indexes for business_users collection...")
        if db.business_users.count_documents({}) > 0:
            handle_index_conflict(db.business_users, [("payroll_id", ASCENDING)], unique=True, name="idx_users_payroll_id")
            handle_index_conflict(db.business_users, [("work_email", ASCENDING)], name="idx_users_work_email")
            
            # Special case - use the existing idx_linking_id name
            handle_index_conflict(db.business_users, [("linking_id", ASCENDING)], name="idx_linking_id")
            
            handle_index_conflict(db.business_users, [("company_id", ASCENDING), ("status", ASCENDING)], name="idx_users_company_status")
            handle_index_conflict(db.business_users, [("venue_id", ASCENDING), ("status", ASCENDING)], name="idx_users_venue_status")
            handle_index_conflict(db.business_users, [("work_area_id", ASCENDING), ("status", ASCENDING)], name="idx_users_workarea_status")
            handle_index_conflict(db.business_users, [("role", ASCENDING)], name="idx_users_role")
            handle_index_conflict(db.business_users, [("last_login", DESCENDING)], name="idx_users_last_login")
        else:
            logger.warning("business_users collection is empty, skipping user-specific indexes")
        
        # Session indexes
        if 'active_sessions' not in db.list_collection_names():
            logger.warning("active_sessions collection does not exist, skipping indexes")
        else:
            logger.info("Setting up indexes for active_sessions collection...")
            handle_index_conflict(db.active_sessions, [("session_id", ASCENDING)], unique=True, name="idx_sessions_id")
            handle_index_conflict(db.active_sessions, [("user_id", ASCENDING)], name="idx_sessions_user_id")
            handle_index_conflict(db.active_sessions, [("last_activity", ASCENDING)], name="idx_sessions_last_activity")
            handle_index_conflict(db.active_sessions, [("created_at", ASCENDING)], name="idx_sessions_created_at")
            handle_index_conflict(db.active_sessions, [("expires_at", ASCENDING)], name="idx_sessions_expires_at")
        
        # Refresh token indexes
        if 'refresh_tokens' not in db.list_collection_names():
            logger.warning("refresh_tokens collection does not exist, skipping indexes")
        else:
            logger.info("Setting up indexes for refresh_tokens collection...")
            handle_index_conflict(db.refresh_tokens, [("token", ASCENDING)], unique=True, name="idx_refresh_token")
            handle_index_conflict(db.refresh_tokens, [("user_id", ASCENDING)], name="idx_refresh_user_id")
            handle_index_conflict(db.refresh_tokens, [("expires_at", ASCENDING)], name="idx_refresh_expires_at")
        
        # Revoked token indexes
        if 'revoked_tokens' not in db.list_collection_names():
            logger.warning("revoked_tokens collection does not exist, skipping indexes")
        else:
            logger.info("Setting up indexes for revoked_tokens collection...")
            handle_index_conflict(db.revoked_tokens, [("jti", ASCENDING)], unique=True, name="idx_revoked_jti")
            handle_index_conflict(db.revoked_tokens, [("expires_at", ASCENDING)], name="idx_revoked_expires_at")
            handle_index_conflict(db.revoked_tokens, [("revoked_at", ASCENDING)], name="idx_revoked_revoked_at")
        
        # MFA indexes
        if 'mfa' not in db.list_collection_names():
            logger.warning("mfa collection does not exist, skipping indexes")
        else:
            logger.info("Setting up indexes for mfa collection...")
            handle_index_conflict(db.mfa, [("payroll_id", ASCENDING)], unique=True, name="idx_mfa_payroll_id")
            handle_index_conflict(db.mfa, [("user_id", ASCENDING)], name="idx_mfa_user_id")
            handle_index_conflict(db.mfa, [("status", ASCENDING)], name="idx_mfa_status")
        
        # Password reset indexes
        if 'password_reset_tokens' not in db.list_collection_names():
            logger.warning("password_reset_tokens collection does not exist, skipping indexes")
        else:
            logger.info("Setting up indexes for password_reset_tokens collection...")
            handle_index_conflict(db.password_reset_tokens, [("token", ASCENDING)], unique=True, name="idx_pwd_reset_token")
            handle_index_conflict(db.password_reset_tokens, [("user_id", ASCENDING)], name="idx_pwd_reset_user_id")
            handle_index_conflict(db.password_reset_tokens, [("expires_at", ASCENDING)], name="idx_pwd_reset_expires_at")
            handle_index_conflict(db.password_reset_tokens, [("used", ASCENDING)], name="idx_pwd_reset_used")
        
        logger.info("Authentication indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error setting up authentication indexes: {str(e)}")
        # Don't raise - allow app to continue with other indexes

def setup_permission_indexes(db):
    """
    Set up indexes for permission-related collections.
    Added validation to check collection existence.
    
    Args:
        db: MongoDB database instance
    """
    try:
        # Role indexes
        if 'business_roles' not in db.list_collection_names():
            logger.warning("business_roles collection does not exist, skipping indexes")
        else:
            logger.info("Setting up indexes for business_roles collection...")
            handle_index_conflict(db.business_roles, [("role_name", ASCENDING)], unique=True, name="idx_roles_name")
        
        # Role assignment indexes
        if 'role_assignments' not in db.list_collection_names():
            logger.warning("role_assignments collection does not exist, skipping indexes")
        else:
            logger.info("Setting up indexes for role_assignments collection...")
            handle_index_conflict(
                db.role_assignments, 
                [("user_id", ASCENDING), ("context.business_id", ASCENDING)], 
                unique=True, 
                name="idx_role_assign_user_business"
            )
            handle_index_conflict(db.role_assignments, [("role_id", ASCENDING)], name="idx_role_assign_role_id")
            handle_index_conflict(db.role_assignments, [("context.business_id", ASCENDING)], name="idx_role_assign_business_id")
            handle_index_conflict(db.role_assignments, [("context.venue_id", ASCENDING)], name="idx_role_assign_venue_id")
            handle_index_conflict(db.role_assignments, [("context.work_area_id", ASCENDING)], name="idx_role_assign_workarea_id")
            handle_index_conflict(db.role_assignments, [("status", ASCENDING)], name="idx_role_assign_status")
        
        # Permission cache indexes
        if 'permission_cache' not in db.list_collection_names():
            logger.warning("permission_cache collection does not exist, skipping indexes")
        else:
            logger.info("Setting up indexes for permission_cache collection...")
            handle_index_conflict(
                db.permission_cache, 
                [("user_id", ASCENDING), ("permission", ASCENDING), ("context_hash", ASCENDING)],
                unique=True,
                name="idx_perm_cache_user_perm_ctx"
            )
            handle_index_conflict(db.permission_cache, [("expires_at", ASCENDING)], name="idx_perm_cache_expires_at")
        
        logger.info("Permission indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error setting up permission indexes: {str(e)}")
        # Don't raise - allow app to continue with other indexes

def setup_business_indexes(db):
    """
    Set up indexes for business-related collections.
    Added validation to check collection existence.
    
    Args:
        db: MongoDB database instance
    """
    try:
        # Business entities indexes
        if 'business_entities' not in db.list_collection_names():
            logger.warning("business_entities collection does not exist, skipping indexes")
        else:
            logger.info("Setting up indexes for business_entities collection...")
            handle_index_conflict(db.business_entities, [("company_id", ASCENDING)], unique=True, name="idx_business_company_id")
            handle_index_conflict(db.business_entities, [("company_name", TEXT)], name="idx_business_company_name_text")
            handle_index_conflict(db.business_entities, [("venues.venue_id", ASCENDING)], name="idx_business_venue_id")
        
        # Business venues indexes
        if 'business_venues' not in db.list_collection_names():
            logger.warning("business_venues collection does not exist, skipping indexes")
        else:
            logger.info("Setting up indexes for business_venues collection...")
            handle_index_conflict(db.business_venues, [("venue_id", ASCENDING)], unique=True, name="idx_venues_venue_id")
            handle_index_conflict(db.business_venues, [("company_id", ASCENDING)], name="idx_venues_company_id")
            handle_index_conflict(db.business_venues, [("venue_name", TEXT)], name="idx_venues_name_text")
            handle_index_conflict(db.business_venues, [("workareas.work_area_id", ASCENDING)], name="idx_venues_workarea_id")
        
        # Business users indexes (additional indexes)
        if 'business_users' not in db.list_collection_names():
            logger.warning("business_users collection does not exist, skipping indexes")
        elif db.business_users.count_documents({}) > 0:
            logger.info("Setting up additional indexes for business_users collection...")
            handle_index_conflict(db.business_users, [("work_email", TEXT)], name="idx_users_work_email_text")
            handle_index_conflict(
                db.business_users, 
                [("first_name", TEXT), ("last_name", TEXT), ("preferred_name", TEXT)],
                name="idx_users_name_text"
            )
        else:
            logger.warning("business_users collection is empty, skipping additional indexes")
        
        logger.info("Business indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error setting up business indexes: {str(e)}")
        # Don't raise - allow app to continue with other indexes

def setup_audit_indexes(db):
    """
    Set up indexes for audit logging.
    Added validation to check collection existence.
    
    Args:
        db: MongoDB database instance
    """
    try:
        # Audit log indexes
        if 'audit_logs' not in db.list_collection_names():
            logger.warning("audit_logs collection does not exist, skipping indexes")
        else:
            logger.info("Setting up indexes for audit_logs collection...")
            handle_index_conflict(db.audit_logs, [("event_type", ASCENDING)], name="idx_audit_event_type")
            handle_index_conflict(db.audit_logs, [("user_id", ASCENDING)], name="idx_audit_user_id")
            handle_index_conflict(db.audit_logs, [("business_id", ASCENDING)], name="idx_audit_business_id")
            handle_index_conflict(db.audit_logs, [("timestamp", DESCENDING)], name="idx_audit_timestamp")
            handle_index_conflict(db.audit_logs, [("ip_address", ASCENDING)], name="idx_audit_ip_address")
        
        logger.info("Audit indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error setting up audit indexes: {str(e)}")
        # Don't raise - allow app to continue with other indexes

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
        # Don't raise - allow app to continue even if indexing fails

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
        # Don't raise the exception to allow the application to continue starting
