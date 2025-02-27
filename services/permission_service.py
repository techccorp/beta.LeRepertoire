# ------------------------------------------------------------
# services/permission_service.py
# ------------------------------------------------------------
"""
Permission service implementing the service layer pattern.
A modularized, more maintainable version of the permission management system.
"""
from typing import Dict, List, Optional, Set, Any, Union, Tuple
from datetime import datetime, timedelta
import logging
import hashlib
import json
from flask import current_app, g
from bson import ObjectId
from pymongo.errors import PyMongoError

from repositories.query_builder import PermissionQueryBuilder

logger = logging.getLogger(__name__)

class PermissionError(Exception):
    """Custom exception for permission-related errors"""
    def __init__(self, message: str, code: str, status_code: int = 403):
        self.message = message
        self.code = code
        self.status_code = status_code
        super().__init__(self.message)

class PermissionService:
    """
    Permission service for role-based access control.
    
    Features:
    - Permission checking and validation
    - Role management
    - Permission inheritance through role hierarchy
    - Caching of permission results
    - Separation of concerns with repository pattern
    """
    
    def __init__(self, db=None, cache_client=None):
        """
        Initialize the Permission Service.
        
        Args:
            db: MongoDB database instance
            cache_client: Optional cache client for permission caching
        """
        self.db = db
        self.cache_client = cache_client
        self.cache_timeout = 300  # 5 minutes in seconds
        
        # Role hierarchy with inheritance
        self.role_hierarchy = self._load_role_hierarchy()
    
    def check_permission(
        self,
        user_id: str,
        permission: str,
        context: Optional[Dict] = None
    ) -> bool:
        """
        Check if user has specific permission in given context.
        
        Args:
            user_id: User's payroll ID
            permission: Permission to check
            context: Optional context dictionary containing business_id, venue_id, etc.
            
        Returns:
            bool: True if user has permission, False otherwise
        """
        try:
            if not user_id:
                return False
                
            # Generate cache key
            cache_key = self._generate_cache_key(user_id, permission, context)
            
            # Check cache first for performance
            cached_result = self._get_cached_permission(cache_key)
            if cached_result is not None:
                return cached_result
                
            # Get database connection
            db = self._get_db()
            
            # Build optimized aggregation pipeline
            pipeline = PermissionQueryBuilder.build_permission_check_pipeline(
                user_id, permission, context
            )
            
            # Execute query
            result = list(db.role_assignments.aggregate(pipeline))
            
            # Check if any documents were returned (user has permission)
            has_permission = len(result) > 0
            
            # Cache result
            self._cache_permission(cache_key, has_permission)
            
            return has_permission
            
        except PyMongoError as e:
            logger.error(f"Database error in permission check: {str(e)}")
            raise PermissionError(
                "Database error during permission check",
                "DATABASE_ERROR",
                500
            )
        except Exception as e:
            logger.error(f"Permission check error: {str(e)}")
            return False
    
    def get_effective_permissions(
        self,
        user_id: str,
        context: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Get all effective permissions for a user in a specific context.
        
        Args:
            user_id: User's payroll ID
            context: Optional context dictionary
            
        Returns:
            List[Dict]: List of effective permissions with values
        """
        try:
            # Generate cache key
            cache_key = f"permissions:{user_id}:{self._context_to_string(context)}"
            
            # Check cache first
            cached_result = self._get_cached_object(cache_key)
            if cached_result is not None:
                return cached_result
                
            # Get database connection
            db = self._get_db()
            
            # Build optimized aggregation pipeline
            pipeline = PermissionQueryBuilder.build_effective_permissions_pipeline(
                user_id, context
            )
            
            # Execute query
            permissions = list(db.role_assignments.aggregate(pipeline))
            
            # Cache results
            self._cache_object(cache_key, permissions)
            
            return permissions
            
        except Exception as e:
            logger.error(f"Error getting effective permissions: {str(e)}")
            return []
    
    def assign_role(
        self,
        user_id: str,
        role_id: str,
        context: Dict,
        assigned_by: Optional[str] = None
    ) -> bool:
        """
        Assign role to a user in a specific context.
        
        Args:
            user_id: User's payroll ID
            role_id: Role ID to assign
            context: Context dictionary with business_id, venue_id, etc.
            assigned_by: Optional ID of user making the assignment
            
        Returns:
            bool: True if assignment successful, False otherwise
        """
        try:
            # Validate role exists
            db = self._get_db()
            role = db.business_roles.find_one({"role_id": role_id})
            
            if not role:
                logger.warning(f"Invalid role ID: {role_id}")
                return False
                
            # Prepare assignment data
            assignment_data = {
                'user_id': user_id,
                'role_id': role_id,
                'context': context,
                'assigned_at': datetime.utcnow(),
                'assigned_by': assigned_by or g.get('user', {}).get('payroll_id'),
                'status': 'active',
                'updated_at': datetime.utcnow()
            }
            
            # Store assignment
            result = db.role_assignments.update_one(
                {
                    'user_id': user_id,
                    'context.business_id': context.get('business_id')
                },
                {'$set': assignment_data},
                upsert=True
            )
            
            if result.modified_count > 0 or result.upserted_id:
                # Clear cache for this user
                self._clear_user_cache(user_id)
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error assigning role: {str(e)}")
            return False
    
    def remove_role(
        self,
        user_id: str,
        context: Dict
    ) -> bool:
        """
        Remove user's role in given context.
        
        Args:
            user_id: User's payroll ID
            context: Context dictionary
            
        Returns:
            bool: True if removal successful, False otherwise
        """
        try:
            db = self._get_db()
            
            # Set status to inactive instead of deleting
            result = db.role_assignments.update_one(
                {
                    'user_id': user_id,
                    'context.business_id': context.get('business_id')
                },
                {
                    '$set': {
                        'status': 'inactive',
                        'updated_at': datetime.utcnow(),
                        'removed_at': datetime.utcnow(),
                        'removed_by': g.get('user', {}).get('payroll_id')
                    }
                }
            )
            
            if result.modified_count > 0:
                # Clear cache for this user
                self._clear_user_cache(user_id)
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error removing role: {str(e)}")
            return False
    
    def create_role(
        self,
        role_name: str,
        permissions: List[Dict],
        role_type: str = 'custom',
        description: Optional[str] = None
    ) -> Optional[str]:
        """
        Create a new role with specified permissions.
        
        Args:
            role_name: Name of the role
            permissions: List of permission objects
            role_type: Type of role ('system', 'business', 'venue', 'custom')
            description: Optional role description
            
        Returns:
            str: New role ID or None if creation failed
        """
        try:
            db = self._get_db()
            
            # Generate unique role ID
            import uuid
            role_id = f"ROLE-{uuid.uuid4().hex[:8].upper()}"
            
            # Prepare role document
            role_doc = {
                'role_id': role_id,
                'role_name': role_name,
                'role_type': role_type,
                'description': description,
                'permissions': permissions,
                'created_at': datetime.utcnow(),
                'created_by': g.get('user', {}).get('payroll_id'),
                'updated_at': datetime.utcnow(),
                'status': 'active'
            }
            
            result = db.business_roles.insert_one(role_doc)
            
            if result.inserted_id:
                # Refresh role hierarchy
                self.role_hierarchy = self._load_role_hierarchy()
                return role_id
                
            return None
            
        except Exception as e:
            logger.error(f"Error creating role: {str(e)}")
            return None
    
    def update_role(
        self,
        role_id: str,
        update_data: Dict
    ) -> bool:
        """
        Update an existing role.
        
        Args:
            role_id: Role ID to update
            update_data: Data to update (can include role_name, permissions, description)
            
        Returns:
            bool: True if update successful, False otherwise
        """
        try:
            db = self._get_db()
            
            # Add update timestamp
            update_data['updated_at'] = datetime.utcnow()
            update_data['updated_by'] = g.get('user', {}).get('payroll_id')
            
            result = db.business_roles.update_one(
                {'role_id': role_id},
                {'$set': update_data}
            )
            
            if result.modified_count > 0:
                # Clear all permission caches since role permissions changed
                self._clear_all_caches()
                
                # Refresh role hierarchy
                self.role_hierarchy = self._load_role_hierarchy()
                
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error updating role: {str(e)}")
            return False
    
    def delete_role(
        self,
        role_id: str
    ) -> bool:
        """
        Delete a role.
        
        Args:
            role_id: Role ID to delete
            
        Returns:
            bool: True if deletion successful, False otherwise
        """
        try:
            db = self._get_db()
            
            # Check if role is in use
            assignments = db.role_assignments.find_one({'role_id': role_id, 'status': 'active'})
            if assignments:
                logger.warning(f"Cannot delete role {role_id} as it is in use")
                return False
                
            # Delete role
            result = db.business_roles.delete_one({'role_id': role_id})
            
            if result.deleted_count > 0:
                # Clear all permission caches
                self._clear_all_caches()
                
                # Refresh role hierarchy
                self.role_hierarchy = self._load_role_hierarchy()
                
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error deleting role: {str(e)}")
            return False
    
    def get_role(
        self,
        role_id: str
    ) -> Optional[Dict]:
        """
        Get role details by ID.
        
        Args:
            role_id: Role ID to get
            
        Returns:
            Dict: Role document or None if not found
        """
        try:
            db = self._get_db()
            return db.business_roles.find_one({'role_id': role_id})
        except Exception as e:
            logger.error(f"Error getting role: {str(e)}")
            return None
    
    def get_roles(
        self,
        role_type: Optional[str] = None,
        status: str = 'active'
    ) -> List[Dict]:
        """
        Get all roles, optionally filtered by type and status.
        
        Args:
            role_type: Optional role type filter
            status: Role status filter (default: 'active')
            
        Returns:
            List[Dict]: List of role documents
        """
        try:
            db = self._get_db()
            
            query = {'status': status}
            if role_type:
                query['role_type'] = role_type
                
            return list(db.business_roles.find(query))
        except Exception as e:
            logger.error(f"Error getting roles: {str(e)}")
            return []
    
    def get_user_roles(
        self,
        user_id: str
    ) -> List[Dict]:
        """
        Get all roles assigned to a user across all contexts.
        
        Args:
            user_id: User's payroll ID
            
        Returns:
            List[Dict]: List of role assignment documents
        """
        try:
            db = self._get_db()
            
            pipeline = [
                {'$match': {'user_id': user_id, 'status': 'active'}},
                {'$lookup': {
                    'from': 'business_roles',
                    'localField': 'role_id',
                    'foreignField': 'role_id',
                    'as': 'role'
                }},
                {'$unwind': '$role'},
                {'$project': {
                    '_id': 0,
                    'role_id': 1,
                    'role_name': '$role.role_name',
                    'context': 1,
                    'assigned_at': 1
                }}
            ]
            
            return list(db.role_assignments.aggregate(pipeline))
        except Exception as e:
            logger.error(f"Error getting user roles: {str(e)}")
            return []
    
    def set_permission_override(
        self,
        user_id: str,
        context: Dict,
        permission: str,
        value: bool,
        override_data: Optional[Dict] = None
    ) -> bool:
        """
        Set a permission override for a user in a specific context.
        
        Args:
            user_id: User's payroll ID
            context: Context dictionary
            permission: Permission to override
            value: Override value (True/False)
            override_data: Additional override data (expiry, approver, etc.)
            
        Returns:
            bool: True if override successful, False otherwise
        """
        try:
            db = self._get_db()
            
            # Get current role assignment
            assignment = db.role_assignments.find_one({
                'user_id': user_id,
                'context.business_id': context.get('business_id'),
                'status': 'active'
            })
            
            if not assignment:
                logger.warning(f"No active role assignment found for user {user_id} in context {context}")
                return False
                
            # Prepare override data
            override = {
                'permission': permission,
                'value': value,
                'created_at': datetime.utcnow(),
                'created_by': g.get('user', {}).get('payroll_id'),
                'expires_at': None
            }
            
            # Add additional override data if provided
            if override_data:
                override.update(override_data)
                
            # Update overrides in assignment
            overrides = assignment.get('overrides', {})
            overrides[permission] = override
            
            result = db.role_assignments.update_one(
                {'_id': assignment['_id']},
                {'$set': {'overrides': overrides, 'updated_at': datetime.utcnow()}}
            )
            
            if result.modified_count > 0:
                # Clear cache for this user
                self._clear_user_cache(user_id)
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error setting permission override: {str(e)}")
            return False
    
    def clear_permission_override(
        self,
        user_id: str,
        context: Dict,
        permission: str
    ) -> bool:
        """
        Clear a permission override for a user in a specific context.
        
        Args:
            user_id: User's payroll ID
            context: Context dictionary
            permission: Permission to clear override for
            
        Returns:
            bool: True if clearing successful, False otherwise
        """
        try:
            db = self._get_db()
            
            # Get current role assignment
            assignment = db.role_assignments.find_one({
                'user_id': user_id,
                'context.business_id': context.get('business_id'),
                'status': 'active'
            })
            
            if not assignment or not assignment.get('overrides', {}).get(permission):
                return False
                
            # Remove override
            overrides = assignment.get('overrides', {})
            if permission in overrides:
                del overrides[permission]
                
            result = db.role_assignments.update_one(
                {'_id': assignment['_id']},
                {'$set': {'overrides': overrides, 'updated_at': datetime.utcnow()}}
            )
            
            if result.modified_count > 0:
                # Clear cache for this user
                self._clear_user_cache(user_id)
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error clearing permission override: {str(e)}")
            return False
    
    def get_permission_overrides(
        self,
        user_id: str,
        context: Dict
    ) -> Dict:
        """
        Get all permission overrides for a user in a specific context.
        
        Args:
            user_id: User's payroll ID
            context: Context dictionary
            
        Returns:
            Dict: Dictionary of permission overrides
        """
        try:
            db = self._get_db()
            
            # Get current role assignment
            assignment = db.role_assignments.find_one({
                'user_id': user_id,
                'context.business_id': context.get('business_id'),
                'status': 'active'
            })
            
            if not assignment:
                return {}
                
            return assignment.get('overrides', {})
            
        except Exception as e:
            logger.error(f"Error getting permission overrides: {str(e)}")
            return {}
    
    def _load_role_hierarchy(self) -> Dict:
        """
        Load role hierarchy from database or use default hierarchy based on organization structure.
        The hierarchy defines which roles inherit permissions from other roles.
        
        Returns:
            Dict: Role hierarchy with inheritance information
        """
        try:
            # Try to load from database
            db = self._get_db()
            if db:
                # Check if role hierarchy collection exists
                if 'role_hierarchy' in db.list_collection_names():
                    hierarchy_doc = db.role_hierarchy.find_one({'_id': 'current'})
                    if hierarchy_doc and 'hierarchy' in hierarchy_doc:
                        return hierarchy_doc['hierarchy']
                        
                # Try to build hierarchy from role_ids collection if available
                if 'role_ids' in db.list_collection_names():
                    try:
                        return self._build_hierarchy_from_role_ids(db)
                    except Exception as e:
                        logger.warning(f"Could not build hierarchy from role_ids: {str(e)}")
            
            # Default hierarchy if not found in database
            # Based on the standard hierarchical structure in the organization
            return {
                'global': {  # Global hierarchy applicable to all departments
                    'admin': ['executive_management', 'senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'executive_management': ['senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'senior_management': ['management', 'dept_head', 'subDept_head', 'employee'],
                    'management': ['dept_head', 'subDept_head', 'employee'],
                    'dept_head': ['subDept_head', 'employee'],
                    'subDept_head': ['employee'],
                    'employee': []
                },
                'admin': {  # Administrative department
                    'admin': ['executive_management', 'senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'executive_management': ['senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'senior_management': ['management', 'dept_head', 'subDept_head', 'employee'],
                    'management': ['dept_head', 'subDept_head', 'employee'],
                    'dept_head': ['subDept_head', 'employee'],
                    'subDept_head': ['employee'],
                    'employee': []
                },
                'boh': {  # Back of House
                    'admin': ['executive_management', 'senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'executive_management': ['senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'senior_management': ['management', 'dept_head', 'subDept_head', 'employee'],
                    'management': ['dept_head', 'subDept_head', 'employee'],
                    'dept_head': ['subDept_head', 'employee'],
                    'subDept_head': ['employee'],
                    'employee': []
                },
                'foh': {  # Front of House
                    'admin': ['executive_management', 'senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'executive_management': ['senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'senior_management': ['management', 'dept_head', 'subDept_head', 'employee'],
                    'management': ['dept_head', 'subDept_head', 'employee'],
                    'dept_head': ['subDept_head', 'employee'],
                    'subDept_head': ['employee'],
                    'employee': []
                },
                'gsh': {  # Guest Services and Housekeeping
                    'admin': ['executive_management', 'senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'executive_management': ['senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'senior_management': ['management', 'dept_head', 'subDept_head', 'employee'],
                    'management': ['dept_head', 'subDept_head', 'employee'],
                    'dept_head': ['subDept_head', 'employee'],
                    'subDept_head': ['employee'],
                    'employee': []
                }
            }
        except Exception as e:
            logger.error(f"Error loading role hierarchy: {str(e)}")
            # Return fallback hierarchy on error
            return {
                'global': {
                    'admin': ['executive_management', 'senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'executive_management': ['senior_management', 'management', 'dept_head', 'subDept_head', 'employee'],
                    'senior_management': ['management', 'dept_head', 'subDept_head', 'employee'],
                    'management': ['dept_head', 'subDept_head', 'employee'],
                    'dept_head': ['subDept_head', 'employee'],
                    'subDept_head': ['employee'],
                    'employee': []
                }
            }

    def _build_hierarchy_from_role_ids(self, db) -> Dict:
        """
        Build role hierarchy from the role_ids collection.
        
        Args:
            db: MongoDB database instance
            
        Returns:
            Dict: Role hierarchy with inheritance information
        """
        # Get all role_ids documents (organized by department)
        role_ids_docs = list(db.role_ids.find())
        
        if not role_ids_docs:
            raise ValueError("No role_ids documents found")
        
        # Define hierarchy levels in order of precedence (highest to lowest)
        hierarchy_levels = [
            "Executive Management",
            "Senior Management",
            "Management",
            "Dept Manager",
            "Sub-Dept Manager",
            "Employee"
        ]
        
        # Convert to database role names
        level_to_role_name = {
            "Executive Management": "executive_management",
            "Senior Management": "senior_management",
            "Management": "management",
            "Dept Manager": "dept_head",
            "Sub-Dept Manager": "subDept_head",
            "Employee": "employee"
        }
        
        # Build hierarchy
        hierarchy = {}
        
        # Add global hierarchy
        hierarchy['global'] = {}
        for i, level in enumerate(hierarchy_levels):
            role_name = level_to_role_name[level]
            # Each level inherits from all levels below it
            hierarchy['global'][role_name] = [level_to_role_name[l] for l in hierarchy_levels[i+1:]]
        
        # Add special admin role with highest privileges
        hierarchy['global']['admin'] = [level_to_role_name[l] for l in hierarchy_levels]
        
        # Add department-specific hierarchies
        for doc in role_ids_docs:
            # Get department code from document ID
            dept_code = doc['_id'].split('_')[0].lower()
            
            # Initialize department hierarchy
            hierarchy[dept_code] = {}
            
            # Add role hierarchy for this department
            for i, level in enumerate(hierarchy_levels):
                # Skip if this level doesn't exist in the document
                if level not in doc:
                    continue
                    
                role_name = level_to_role_name[level]
                # Each level inherits from all levels below it
                hierarchy[dept_code][role_name] = [level_to_role_name[l] for l in hierarchy_levels[i+1:]]
            
            # Add admin role with highest privileges
            hierarchy[dept_code]['admin'] = [level_to_role_name[l] for l in hierarchy_levels]
        
        return hierarchy
    
    def _get_db(self):
        """Get MongoDB database connection."""
        if self.db:
            return self.db
            
        if hasattr(current_app, 'mongo'):
            return current_app.mongo.db
            
        if 'mongo' in g:
            return g.mongo.db
            
        return None
    
    def _generate_cache_key(
        self,
        user_id: str,
        permission: str,
        context: Optional[Dict]
    ) -> str:
        """Generate unique cache key for permission check."""
        context_str = self._context_to_string(context)
        return f"perm:{user_id}:{permission}:{context_str}"
    
    def _context_to_string(
        self,
        context: Optional[Dict]
    ) -> str:
        """Convert context dictionary to string for cache key."""
        if not context:
            return ''
            
        # Sort keys for consistent hash generation
        sorted_items = sorted(context.items())
        return ':'.join(f"{k}={v}" for k, v in sorted_items)
    
    def _get_cached_permission(
        self,
        cache_key: str
    ) -> Optional[bool]:
        """Get cached permission result if available."""
        # Try in-memory cache first (local to this process)
        if hasattr(self, 'local_cache'):
            if cache_key in self.local_cache:
                value, expiry = self.local_cache[cache_key]
                if datetime.utcnow() < expiry:
                    return value
                # Expired
                del self.local_cache[cache_key]
        
        # Try Redis cache if available
        if self.cache_client:
            try:
                result = self.cache_client.get(cache_key)
                if result is not None:
                    return result == b'1'
            except Exception as e:
                logger.warning(f"Redis cache error: {str(e)}")
        
        return None
    
    def _get_cached_object(
        self,
        cache_key: str
    ) -> Optional[Any]:
        """Get cached object if available."""
        # Try in-memory cache first
        if hasattr(self, 'local_cache'):
            if cache_key in self.local_cache:
                value, expiry = self.local_cache[cache_key]
                if datetime.utcnow() < expiry:
                    return value
                # Expired
                del self.local_cache[cache_key]
        
        # Try Redis cache if available
        if self.cache_client:
            try:
                result = self.cache_client.get(cache_key)
                if result is not None:
                    return json.loads(result)
            except Exception as e:
                logger.warning(f"Redis cache error: {str(e)}")
        
        return None
    
    def _cache_permission(
        self,
        cache_key: str,
        value: bool
    ) -> None:
        """Cache permission check result."""
        # Store in local memory cache
        if not hasattr(self, 'local_cache'):
            self.local_cache = {}
            
        expiry = datetime.utcnow() + timedelta(seconds=self.cache_timeout)
        self.local_cache[cache_key] = (value, expiry)
        
        # Store in Redis if available
        if self.cache_client:
            try:
                self.cache_client.setex(
                    cache_key,
                    self.cache_timeout,
                    '1' if value else '0'
                )
            except Exception as e:
                logger.warning(f"Redis cache error: {str(e)}")
    
    def _cache_object(
        self,
        cache_key: str,
        value: Any
    ) -> None:
        """Cache an object."""
        # Store in local memory cache
        if not hasattr(self, 'local_cache'):
            self.local_cache = {}
            
        expiry = datetime.utcnow() + timedelta(seconds=self.cache_timeout)
        self.local_cache[cache_key] = (value, expiry)
        
        # Store in Redis if available
        if self.cache_client:
            try:
                self.cache_client.setex(
                    cache_key,
                    self.cache_timeout,
                    json.dumps(value)
                )
            except Exception as e:
                logger.warning(f"Redis cache error: {str(e)}")
    
    def _clear_user_cache(
        self,
        user_id: str
    ) -> None:
        """Clear all cached permissions for a user."""
        # Clear local cache
        if hasattr(self, 'local_cache'):
            prefix = f"perm:{user_id}:"
            keys_to_remove = [k for k in self.local_cache.keys() if k.startswith(prefix)]
            for key in keys_to_remove:
                del self.local_cache[key]
        
        # Clear Redis cache if available
        if self.cache_client:
            try:
                # Get all keys with prefix and delete them
                for key in self.cache_client.scan_iter(f"perm:{user_id}:*"):
                    self.cache_client.delete(key)
            except Exception as e:
                logger.warning(f"Redis cache error: {str(e)}")
    
    def _clear_all_caches(self) -> None:
        """Clear all permission caches (useful after role updates)."""
        # Clear local cache
        if hasattr(self, 'local_cache'):
            self.local_cache = {}
        
        # Clear Redis cache if available
        if self.cache_client:
            try:
                # Delete all permission keys
                for key in self.cache_client.scan_iter("perm:*"):
                    self.cache_client.delete(key)
                    
                # Delete permissions keys
                for key in self.cache_client.scan_iter("permissions:*"):
                    self.cache_client.delete(key)
            except Exception as e:
                logger.warning(f"Redis cache error: {str(e)}")

# Helper function to initialize the permission service
def init_permission_service(app, cache_client=None):
    """
    Initialize the Permission Service with the application context.
    
    Args:
        app: Flask application instance
        cache_client: Optional Redis client for permission caching
        
    Returns:
        PermissionService: Initialized permission service
    """
    try:
        # Get database from app
        db = app.mongo.db if hasattr(app, 'mongo') else None
        
        # Create service
        permission_service = PermissionService(db, cache_client)
        
        # Store in app context
        app.permission_service = permission_service
        
        logger.info("Permission Service initialized successfully")
        return permission_service
        
    except Exception as e:
        logger.error(f"Failed to initialize Permission Service: {str(e)}")
        raise
