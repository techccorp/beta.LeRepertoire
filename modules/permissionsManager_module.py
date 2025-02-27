# ------------------------------------------------------------
# Permission Manager Module
# -----------------------
"""Core permission management system providing role-based access control with inheritance
and caching capabilities.

This module handles:
- Permission checking and validation
- Role hierarchy management
- Permission inheritance
- Caching of permission results
- Integration with MongoDB for persistence
"""
from typing import Dict, List, Optional, Union, Set, Any
from datetime import datetime, timedelta
from flask import current_app, g, session
from bson import ObjectId
import logging
from functools import lru_cache
from config import Config
from pymongo.errors import PyMongoError

# Configure module logger
logger = logging.getLogger(__name__)

class PermissionError(Exception):
    """Custom exception for permission-related errors"""
    def __init__(self, message: str, code: str, status_code: int = 403):
        self.message = message
        self.code = code
        self.status_code = status_code
        super().__init__(self.message)

class PermissionManager:
    """
    Enhanced Permission Manager with role hierarchy and inheritance.
    
    Features:
    - Role-based permission management
    - Permission inheritance through role hierarchy
    - Context-aware permission checking
    - Efficient caching of permission results
    - MongoDB integration for persistence
    """
    
    def __init__(self, db):
        """
        Initialize the Permission Manager.
        
        Args:
            db: MongoDB database instance
        """
        self.db = db
        self.cache = {}
        self.cache_timeout = 300  # 5 minutes
        
        # Define role hierarchy with inheritance
        self.role_hierarchy = {
            'system': {
                'super_admin': ['admin', 'manager', 'user'],
                'admin': ['manager', 'user'],
                'manager': ['user'],
                'user': []
            },
            'business': {
                'owner': ['admin', 'manager', 'staff', 'employee'],
                'admin': ['manager', 'staff', 'employee'],
                'manager': ['staff', 'employee'],
                'staff': ['employee'],
                'employee': []
            },
            'venue': {
                'venue_manager': ['supervisor', 'staff', 'employee'],
                'supervisor': ['staff', 'employee'],
                'staff': ['employee'],
                'employee': []
            }
        }
        
        # Enhanced permission definitions with inheritance
        self.permission_definitions = {
            'system': {
                'super_admin': ['all'],
                'admin': [
                    'manage_users', 'view_logs', 'manage_settings',
                    'manage_venues', 'manage_permissions'
                ],
                'manager': [
                    'manage_assigned_venues', 'view_logs',
                    'view_settings', 'manage_staff'
                ],
                'user': ['view_own_profile', 'update_own_profile']
            },
            'business': {
                'owner': ['all'],
                'admin': [
                    'manage_venues', 'manage_users', 'view_reports',
                    'manage_settings', 'manage_inventory', 'manage_staff'
                ],
                'manager': [
                    'manage_assigned_venues', 'view_reports',
                    'manage_staff', 'view_inventory', 'create_orders'
                ],
                'staff': [
                    'view_assigned_areas', 'manage_assigned_tasks',
                    'view_inventory', 'update_orders'
                ],
                'employee': ['view_own_schedule', 'view_assigned_tasks']
            },
            'venue': {
                'venue_manager': [
                    'manage_venue', 'manage_staff', 'view_reports',
                    'manage_inventory', 'manage_schedules'
                ],
                'supervisor': [
                    'manage_assigned_areas', 'view_staff',
                    'create_reports', 'update_inventory'
                ],
                'staff': [
                    'view_assigned_areas', 'update_task_status',
                    'view_inventory'
                ],
                'employee': ['view_own_tasks', 'update_own_status']
            }
        }

    def check_permission(
        self,
        user_id: str,
        permission: str,
        context: Optional[Dict] = None
    ) -> bool:
        """
        Check if user has specific permission in given context.
        
        Args:
            user_id: User identifier
            permission: Permission to check
            context: Optional context dictionary containing business_id, venue_id, etc.
            
        Returns:
            bool: True if user has permission, False otherwise
            
        Raises:
            PermissionError: If context validation fails
        """
        try:
            if not user_id:
                return False

            cache_key = self._generate_cache_key(user_id, permission, context)
            cached_result = self._get_cached_permission(cache_key)
            if cached_result is not None:
                return cached_result

            # Get user roles and check permissions
            user_roles = self._get_user_roles(user_id, context)
            if not user_roles:
                return False

            # Get inherited roles and permissions
            all_roles = self._get_all_roles(user_roles, context)
            user_permissions = self._get_combined_permissions(all_roles, context)

            # Check permission
            has_permission = permission in user_permissions or 'all' in user_permissions
            
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
    ) -> List[str]:
        """
        Get all effective permissions including inherited ones.
        
        Args:
            user_id: User identifier
            context: Optional context dictionary
            
        Returns:
            List[str]: List of all effective permissions
        """
        try:
            user_roles = self._get_user_roles(user_id, context)
            all_roles = self._get_all_roles(user_roles, context)
            return self._get_combined_permissions(all_roles, context)
        except Exception as e:
            logger.error(f"Error getting effective permissions: {str(e)}")
            return []

    def assign_role(
        self,
        user_id: str,
        role: str,
        context: Dict,
        assigned_by: Optional[str] = None
    ) -> bool:
        """
        Assign role with validation and inheritance handling.
        
        Args:
            user_id: User identifier
            role: Role to assign
            context: Context dictionary with business_id, venue_id, etc.
            assigned_by: Optional ID of user making the assignment
            
        Returns:
            bool: True if assignment successful, False otherwise
            
        Raises:
            PermissionError: If role assignment fails validation
        """
        try:
            context_type = self._get_context_type(context)
            if role not in self.permission_definitions[context_type]:
                raise PermissionError(
                    f"Invalid role for context: {role}",
                    'INVALID_ROLE'
                )

            # Prepare assignment data
            assignment_data = {
                'role': role,
                'assigned_at': datetime.utcnow(),
                'assigned_by': assigned_by or session.get('user_id'),
                'inherited_roles': self._get_inherited_roles(role, context),
                'status': 'active',
                'updated_at': datetime.utcnow()
            }

            result = self._store_role_assignment(user_id, assignment_data, context)
            if result:
                self._clear_user_cache(user_id)
                return True
                
            return False

        except Exception as e:
            logger.error(f"Error assigning role: {str(e)}")
            return False

    def remove_role(self, user_id: str, context: Dict) -> bool:
        """
        Remove user's role in given context.
        
        Args:
            user_id (str): User identifier
            context (Dict): Context dictionary
            
        Returns:
            bool: True if removal successful, False otherwise
        """
        try:
            context_type = self._get_context_type(context)
            collection = self._get_collection_for_context(context_type)
            
            query = self._build_removal_query(user_id, context)
            update = self._build_removal_update(context_type, user_id)
            
            result = collection.update_one(query, update)
            
            if result.modified_count > 0:
                self._clear_user_cache(user_id)
                return True
                
            return False

        except Exception as e:
            logger.error(f"Error removing role: {str(e)}")
            return False

    @lru_cache(maxsize=1000)
    def _get_inherited_roles(self, role: str, context: Dict) -> List[str]:
        """Get all roles inherited from the given role."""
        context_type = self._get_context_type(context)
        hierarchy = self.role_hierarchy.get(context_type, {})
        return hierarchy.get(role, [])

    def _get_context_type(self, context: Optional[Dict]) -> str:
        """Determine context type based on provided context."""
        if not context:
            return 'system'
        if context.get('work_area_id'):
            return 'venue'
        if context.get('venue_id'):
            return 'venue'
        if context.get('business_id'):
            return 'business'
        return 'system'

    def _get_all_roles(self, base_roles: List[str], context: Dict) -> Set[str]:
        """Get all roles including inherited ones."""
        all_roles = set()
        for role in base_roles:
            all_roles.add(role)
            all_roles.update(self._get_inherited_roles(role, context))
        return all_roles

    def _get_combined_permissions(
        self,
        roles: Set[str],
        context: Dict
    ) -> List[str]:
        """Get combined permissions for all roles in context."""
        permissions = set()
        context_type = self._get_context_type(context)
        
        for role in roles:
            role_permissions = self.permission_definitions[context_type].get(role, [])
            permissions.update(role_permissions)
            
        return list(permissions)

    def _generate_cache_key(
        self,
        user_id: str,
        permission: str,
        context: Optional[Dict]
    ) -> str:
        """Generate unique cache key for permission check."""
        context_str = ':'.join(f"{k}={v}" for k, v in sorted(context.items())) if context else ''
        return f"perm:{user_id}:{permission}:{context_str}"

    def _get_cached_permission(self, cache_key: str) -> Optional[bool]:
        """Get cached permission result if available and not expired."""
        if cache_key in self.cache:
            result, timestamp = self.cache[cache_key]
            if datetime.utcnow() - timestamp < timedelta(seconds=self.cache_timeout):
                return result
            del self.cache[cache_key]
        return None

    def _cache_permission(self, cache_key: str, result: bool) -> None:
        """Cache permission check result with timestamp."""
        self.cache[cache_key] = (result, datetime.utcnow())

    def _clear_user_cache(self, user_id: str) -> None:
        """Clear all cached permissions for specific user."""
        prefix = f"perm:{user_id}:"
        keys_to_remove = [k for k in self.cache.keys() if k.startswith(prefix)]
        for key in keys_to_remove:
            self.cache.pop(key, None)

    def _get_user_roles(
        self,
        user_id: str,
        context: Optional[Dict] = None
    ) -> List[str]:
        """
        Get user's roles in given context.
        
        Args:
            user_id: User identifier
            context: Optional context dictionary
            
        Returns:
            List[str]: List of user's roles
        """
        cache_key = f"roles:{user_id}:{context.get('business_id', '')}:{context.get('venue_id', '')}"
        
        if cache_key in self.cache:
            roles, timestamp = self.cache[cache_key]
            if datetime.utcnow() - timestamp < timedelta(seconds=self.cache_timeout):
                return roles

        roles = []
        try:
            # Get business-level role
            if context and context.get('business_id'):
                business_user = self.db[Config.COLLECTION_BUSINESS_USERS].find_one({
                    'user_id': user_id,
                    'business_id': context['business_id'],
                    'status': 'active'
                })
                if business_user:
                    roles.append(business_user['role'])

            # Get venue-level role if applicable
            if context and context.get('venue_id'):
                venue_staff = self._get_venue_role(user_id, context)
                if venue_staff:
                    roles.append(venue_staff['role'])

            # Get work area role if applicable
            if context and context.get('work_area_id'):
                work_area_staff = self._get_work_area_role(user_id, context)
                if work_area_staff:
                    roles.append(work_area_staff['role'])

            self.cache[cache_key] = (roles, datetime.utcnow())
            return roles

        except Exception as e:
            logger.error(f"Error getting user roles: {str(e)}")
            return []

    def _get_venue_role(self, user_id: str, context: Dict) -> Optional[Dict]:
        """Get user's role at venue level."""
        venue_staff = self.db[Config.COLLECTION_BUSINESSES].find_one(
            {
                'business_id': context['business_id'],
                'venues.venue_id': context['venue_id'],
                'venues.staff.user_id': user_id,
                'venues.staff.status': 'active'
            },
            {'venues.staff.$': 1}
        )
        if venue_staff and venue_staff.get('venues'):
            staff = venue_staff['venues'][0].get('staff', [])
            return staff[0] if staff else None
        return None

    def _get_work_area_role(self, user_id: str, context: Dict) -> Optional[Dict]:
        """Get user's role at work area level.
        
        Args:
            user_id (str): User identifier
            context (Dict): Context dictionary containing business, venue, and work area IDs
            
        Returns:
            Optional[Dict]: Staff document if found, None otherwise
            
        Raises:
            PyMongoError: If database operation fails
        """
        try:
            # Build query with proper indexes
            work_area_staff = self.db[Config.COLLECTION_BUSINESSES].find_one(
                {
                    'business_id': context['business_id'],
                    'venues.venue_id': context['venue_id'],
                    'venues.work_areas.work_area_id': context['work_area_id'],
                    'venues.work_areas.staff.user_id': user_id,
                    'venues.work_areas.staff.status': 'active'
                },
                # Optimize projection to return only needed fields
                {
                    'venues.$': {
                        '$elemMatch': {
                            'venue_id': context['venue_id'],
                            'work_areas': {
                                '$elemMatch': {
                                    'work_area_id': context['work_area_id'],
                                    'staff': {
                                        '$elemMatch': {
                                            'user_id': user_id,
                                            'status': 'active'
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            )
            
            # Navigate the document structure safely
            if work_area_staff and work_area_staff.get('venues'):
                venue = work_area_staff['venues'][0]
                if venue.get('work_areas'):
                    work_area = venue['work_areas'][0]
                    staff = work_area.get('staff', [])
                    if staff:
                        staff_member = staff[0]
                        # Return only necessary fields
                        return {
                            'user_id': staff_member['user_id'],
                            'role': staff_member['role'],
                            'status': staff_member['status'],
                            'assigned_at': staff_member.get('assigned_at'),
                            'permissions': staff_member.get('permissions', [])
                        }
            
            return None

        except PyMongoError as e:
            logger.error(f"Database error in _get_work_area_role: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error in _get_work_area_role: {str(e)}")
            return None
    
    def _store_role_assignment(
        self,
        user_id: str,
        assignment_data: Dict,
        context: Dict
    ) -> bool:
        """
        Store role assignment in appropriate collection based on context.
        
        Args:
            user_id: User identifier
            assignment_data: Role assignment data
            context: Context dictionary
            
        Returns:
            bool: True if assignment successful, False otherwise
        """
        try:
            context_type = self._get_context_type(context)
            
            if context_type == 'business':
                return self._store_business_role(user_id, assignment_data, context)
            elif context_type == 'venue':
                return self._store_venue_role(user_id, assignment_data, context)
            elif context_type == 'work_area':
                return self._store_work_area_role(user_id, assignment_data, context)
            else:
                return self._store_system_role(user_id, assignment_data)

        except Exception as e:
            logger.error(f"Error storing role assignment: {str(e)}")
            return False

    def _store_business_role(
        self,
        user_id: str,
        assignment_data: Dict,
        context: Dict
    ) -> bool:
        """Store business-level role assignment."""
        result = self.db[Config.COLLECTION_BUSINESS_USERS].update_one(
            {
                'user_id': user_id,
                'business_id': context['business_id']
            },
            {'$set': assignment_data},
            upsert=True
        )
        return bool(result.modified_count or result.upserted_id)

    def _store_venue_role(
        self,
        user_id: str,
        assignment_data: Dict,
        context: Dict
    ) -> bool:
        """Store venue-level role assignment."""
        result = self.db[Config.COLLECTION_BUSINESSES].update_one(
            {
                'business_id': context['business_id'],
                'venues.venue_id': context['venue_id']
            },
            {
                '$set': {
                    'venues.$[venue].staff.$[staff]': assignment_data
                }
            },
            array_filters=[
                {'venue.venue_id': context['venue_id']},
                {'staff.user_id': user_id}
            ],
            upsert=True
        )
        return bool(result.modified_count or result.upserted_id)

    def _store_work_area_role(
        self,
        user_id: str,
        assignment_data: Dict,
        context: Dict
    ) -> bool:
        """Store work area-level role assignment."""
        result = self.db[Config.COLLECTION_BUSINESSES].update_one(
            {
                'business_id': context['business_id'],
                'venues.venue_id': context['venue_id'],
                'venues.work_areas.work_area_id': context['work_area_id']
            },
            {
                '$set': {
                    'venues.$[venue].work_areas.$[area].staff.$[staff]': assignment_data
                }
            },
            array_filters=[
                {'venue.venue_id': context['venue_id']},
                {'area.work_area_id': context['work_area_id']},
                {'staff.user_id': user_id}
            ],
            upsert=True
        )
        return bool(result.modified_count or result.upserted_id)

    def _store_system_role(self, user_id: str, assignment_data: Dict) -> bool:
        """Store system-level role assignment."""
        result = self.db[Config.COLLECTION_USERS].update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'role': assignment_data['role'],
                'role_updated_at': datetime.utcnow(),
                'role_updated_by': assignment_data['assigned_by']
            }},
            upsert=True
        )
        return bool(result.modified_count or result.upserted_id)

    def _build_removal_query(self, user_id: str, context: Dict) -> Dict:
        """Build query for role removal based on context."""
        context_type = self._get_context_type(context)
        if context_type == 'business':
            return {
                'business_id': context['business_id'],
                'user_id': user_id
            }
        elif context_type == 'venue':
            return {
                'business_id': context['business_id'],
                'venues.venue_id': context['venue_id'],
                'venues.staff.user_id': user_id
            }
        elif context_type == 'work_area':
            return {
                'business_id': context['business_id'],
                'venues.venue_id': context['venue_id'],
                'venues.work_areas.work_area_id': context['work_area_id'],
                'venues.work_areas.staff.user_id': user_id
            }
        return {'_id': ObjectId(user_id)}

    def _build_removal_update(self, context_type: str, user_id: str) -> Dict:
        """Build update operation for role removal."""
        if context_type == 'business':
            return {'$unset': {'role': '', 'status': ''}}
        elif context_type == 'venue':
            return {'$pull': {'venues.$.staff': {'user_id': user_id}}}
        elif context_type == 'work_area':
            return {
                '$pull': {
                    'venues.$[venue].work_areas.$[area].staff': {
                        'user_id': user_id
                    }
                }
            }
        return {'$unset': {'role': ''}}

    def _get_collection_for_context(self, context_type: str) -> str:
        """Get appropriate collection name for context type."""
        if context_type == 'business':
            return Config.COLLECTION_BUSINESS_USERS
        elif context_type in ('venue', 'work_area'):
            return Config.COLLECTION_BUSINESSES
        return Config.COLLECTION_USERS

    def cleanup(self) -> None:
        """Cleanup resources and clear caches."""
        try:
            self.cache.clear()
            self._get_inherited_roles.cache_clear()
        except Exception as e:
            logger.error(f"Error during permission manager cleanup: {str(e)}")

# Module-level type hints for better code documentation
RoleHierarchy = Dict[str, List[str]]
PermissionDefinitions = Dict[str, Dict[str, List[str]]]
AssignmentData = Dict[str, Union[str, datetime, List[str]]]

def init_permission_manager(app):
    """
    Initialize the Permission Manager with the application context.
    
    Args:
        app: Flask application instance
    
    Returns:
        PermissionManager: Initialized permission manager instance
    """
    try:
        # Initialize permission manager with app's MongoDB instance
        permission_manager = PermissionManager(app.mongo.db)
        
        # Store permission manager in app context
        app.permission_manager = permission_manager
        
        logger.info("Permission Manager initialized successfully")
        return permission_manager
        
    except Exception as e:
        logger.error(f"Failed to initialize Permission Manager: {str(e)}")
        raise 

# Module exports
__all__ = ['PermissionManager', 'init_permission_manager', 'PermissionError']
