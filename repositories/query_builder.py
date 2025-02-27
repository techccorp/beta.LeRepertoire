# ------------------------------------------------------------
# repositories/query_builder.py
# ------------------------------------------------------------
"""
MongoDB aggregation query builder for optimized database operations.
Provides reusable pipeline builders for complex queries.
"""
from typing import Dict, List, Any, Optional, Union
from pymongo import ASCENDING, DESCENDING
from bson import ObjectId

class AggregationBuilder:
    """
    Builder for MongoDB aggregation pipelines.
    
    Features:
    - Fluent interface for building pipelines
    - Predefined pipeline stages for common operations
    - Optimized query patterns for MongoDB
    """
    
    def __init__(self):
        """Initialize an empty pipeline."""
        self.pipeline = []
    
    def match(self, query: Dict) -> 'AggregationBuilder':
        """
        Add $match stage to pipeline.
        
        Args:
            query: Match query
            
        Returns:
            AggregationBuilder: Self for chaining
        """
        self.pipeline.append({"$match": query})
        return self
    
    def lookup(self, from_collection: str, local_field: str, 
               foreign_field: str, as_field: str) -> 'AggregationBuilder':
        """
        Add $lookup stage to pipeline.
        
        Args:
            from_collection: Collection to join
            local_field: Field from current collection
            foreign_field: Field from foreign collection
            as_field: Output field name
            
        Returns:
            AggregationBuilder: Self for chaining
        """
        self.pipeline.append({
            "$lookup": {
                "from": from_collection,
                "localField": local_field,
                "foreignField": foreign_field,
                "as": as_field
            }
        })
        return self
    
    def unwind(self, path: str, preserve_null_and_empty: bool = False) -> 'AggregationBuilder':
        """
        Add $unwind stage to pipeline.
        
        Args:
            path: Path to array field
            preserve_null_and_empty: Whether to preserve null/empty arrays
            
        Returns:
            AggregationBuilder: Self for chaining
        """
        self.pipeline.append({
            "$unwind": {
                "path": path,
                "preserveNullAndEmptyArrays": preserve_null_and_empty
            }
        })
        return self
    
    def project(self, projection: Dict) -> 'AggregationBuilder':
        """
        Add $project stage to pipeline.
        
        Args:
            projection: Projection specification
            
        Returns:
            AggregationBuilder: Self for chaining
        """
        self.pipeline.append({"$project": projection})
        return self
    
    def group(self, group_spec: Dict) -> 'AggregationBuilder':
        """
        Add $group stage to pipeline.
        
        Args:
            group_spec: Group specification
            
        Returns:
            AggregationBuilder: Self for chaining
        """
        self.pipeline.append({"$group": group_spec})
        return self
    
    def sort(self, sort_spec: Dict) -> 'AggregationBuilder':
        """
        Add $sort stage to pipeline.
        
        Args:
            sort_spec: Sort specification
            
        Returns:
            AggregationBuilder: Self for chaining
        """
        self.pipeline.append({"$sort": sort_spec})
        return self
    
    def limit(self, limit: int) -> 'AggregationBuilder':
        """
        Add $limit stage to pipeline.
        
        Args:
            limit: Maximum number of documents
            
        Returns:
            AggregationBuilder: Self for chaining
        """
        self.pipeline.append({"$limit": limit})
        return self
    
    def skip(self, skip: int) -> 'AggregationBuilder':
        """
        Add $skip stage to pipeline.
        
        Args:
            skip: Number of documents to skip
            
        Returns:
            AggregationBuilder: Self for chaining
        """
        self.pipeline.append({"$skip": skip})
        return self
    
    def add_fields(self, fields: Dict) -> 'AggregationBuilder':
        """
        Add $addFields stage to pipeline.
        
        Args:
            fields: Fields to add
            
        Returns:
            AggregationBuilder: Self for chaining
        """
        self.pipeline.append({"$addFields": fields})
        return self
    
    def facet(self, facets: Dict) -> 'AggregationBuilder':
        """
        Add $facet stage to pipeline.
        
        Args:
            facets: Facet specification
            
        Returns:
            AggregationBuilder: Self for chaining
        """
        self.pipeline.append({"$facet": facets})
        return self
    
    def count(self, count_field: str = 'count') -> 'AggregationBuilder':
        """
        Add $count stage to pipeline.
        
        Args:
            count_field: Name of count field
            
        Returns:
            AggregationBuilder: Self for chaining
        """
        self.pipeline.append({"$count": count_field})
        return self
    
    def build(self) -> List[Dict]:
        """
        Build the aggregation pipeline.
        
        Returns:
            List[Dict]: Completed pipeline
        """
        return self.pipeline.copy()


class UserQueryBuilder:
    """
    Builder for user-related MongoDB aggregation queries.
    
    Features:
    - Predefined query patterns for common user operations
    - Optimized aggregation pipelines for user data
    - Pagination and filtering support
    """
    
    @staticmethod
    def build_user_search_pipeline(
        search_text: Optional[str] = None,
        filters: Optional[Dict] = None,
        business_id: Optional[str] = None,
        venue_id: Optional[str] = None,
        work_area_id: Optional[str] = None,
        role: Optional[str] = None,
        status: Optional[str] = None,
        sort_field: str = 'last_name',
        sort_order: int = ASCENDING,
        page: int = 1,
        page_size: int = 20
    ) -> List[Dict]:
        """
        Build pipeline for searching users with filtering, sorting, and pagination.
        
        Args:
            search_text: Optional text search query
            filters: Additional filters
            business_id: Optional business ID filter
            venue_id: Optional venue ID filter
            work_area_id: Optional work area ID filter
            role: Optional role filter
            status: Optional status filter
            sort_field: Field to sort by
            sort_order: Sort direction (ASCENDING or DESCENDING)
            page: Page number (1-based)
            page_size: Number of items per page
            
        Returns:
            List[Dict]: Aggregation pipeline
        """
        builder = AggregationBuilder()
        
        # Start with match stage for all filters
        match_query = {}
        
        # Add search text query if provided
        if search_text:
            # Create text search for email, name fields
            text_fields = [
                {"work_email": {"$regex": search_text, "$options": "i"}},
                {"first_name": {"$regex": search_text, "$options": "i"}},
                {"last_name": {"$regex": search_text, "$options": "i"}},
                {"preferred_name": {"$regex": search_text, "$options": "i"}},
                {"payroll_id": {"$regex": search_text, "$options": "i"}}
            ]
            match_query["$or"] = text_fields
        
        # Add core filters
        if business_id:
            match_query["company_id"] = business_id
        
        if venue_id:
            match_query["venue_id"] = venue_id
        
        if work_area_id:
            match_query["work_area_id"] = work_area_id
        
        if role:
            match_query["role"] = role
        
        if status:
            if status == 'active':
                match_query["status"] = {"$ne": "inactive"}
            else:
                match_query["status"] = status
        
        # Add any additional filters
        if filters:
            for key, value in filters.items():
                match_query[key] = value
        
        # Build pipeline
        builder.match(match_query)
        
        # Add facet for pagination and metadata
        builder.facet({
            "metadata": [
                {"$count": "total"}
            ],
            "data": [
                {"$sort": {sort_field: sort_order}},
                {"$skip": (page - 1) * page_size},
                {"$limit": page_size}
            ]
        })
        
        # Add final project to reshape output
        builder.project({
            "metadata": {
                "$ifNull": [{"$arrayElemAt": ["$metadata", 0]}, {"total": 0}]
            },
            "data": 1,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_pages": {
                    "$ceil": {
                        "$divide": [
                            {"$ifNull": [{"$arrayElemAt": ["$metadata.total", 0]}, 0]},
                            page_size
                        ]
                    }
                }
            }
        })
        
        return builder.build()
    
    @staticmethod
    def build_user_detail_pipeline(
        user_id: Union[str, ObjectId],
        include_permissions: bool = False,
        include_sessions: bool = False
    ) -> List[Dict]:
        """
        Build pipeline for detailed user information including related data.
        
        Args:
            user_id: User MongoDB ID
            include_permissions: Whether to include effective permissions
            include_sessions: Whether to include active sessions
            
        Returns:
            List[Dict]: Aggregation pipeline
        """
        # Convert string ID to ObjectId if needed
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        
        builder = AggregationBuilder()
        
        # Match user
        builder.match({"_id": user_id})
        
        # Add business lookup
        builder.lookup(
            from_collection="business_entities",
            local_field="company_id",
            foreign_field="company_id",
            as_field="business_details"
        )
        
        # Add venue lookup
        builder.lookup(
            from_collection="business_venues",
            local_field="venue_id",
            foreign_field="venue_id",
            as_field="venue_details"
        )
        
        # Include permissions if requested
        if include_permissions:
            builder.lookup(
                from_collection="role_assignments",
                local_field="payroll_id",
                foreign_field="user_id",
                as_field="role_assignments"
            )
            
            builder.lookup(
                from_collection="business_roles",
                local_field="role_assignments.role_id",
                foreign_field="role_id",
                as_field="roles"
            )
        
        # Include sessions if requested
        if include_sessions:
            builder.lookup(
                from_collection="active_sessions",
                local_field="payroll_id",
                foreign_field="user_id",
                as_field="sessions"
            )
        
        # Project final result
        project = {
            "_id": 1,
            "linking_id": 1,
            "payroll_id": 1,
            "company_id": 1,
            "company_name": 1,
            "venue_id": 1,
            "venue_name": 1,
            "work_area_id": 1,
            "work_area_name": 1,
            "role": 1,
            "first_name": 1,
            "last_name": 1,
            "preferred_name": 1,
            "date_of_birth": 1,
            "address": 1,
            "suburb": 1,
            "state": 1,
            "post_code": 1,
            "personal_contact": 1,
            "work_email": 1,
            "employment_details": 1,
            "leave_entitlements": 1,
            "accrued_employment": 1,
            "created_at": 1,
            "last_login": 1,
            "business_details": {
                "$arrayElemAt": ["$business_details", 0]
            },
            "venue_details": {
                "$arrayElemAt": ["$venue_details", 0]
            }
        }
        
        # Add permissions fields if requested
        if include_permissions:
            project["roles"] = 1
            project["role_assignments"] = 1
        
        # Add sessions field if requested
        if include_sessions:
            project["sessions"] = {
                "$filter": {
                    "input": "$sessions",
                    "as": "session",
                    "cond": {
                        "$gt": ["$$session.expires_at", {"$date": datetime.utcnow()}]
                    }
                }
            }
        
        builder.project(project)
        
        return builder.build()


class PermissionQueryBuilder:
    """
    Builder for permission-related MongoDB aggregation queries.
    
    Features:
    - Predefined query patterns for permission checks
    - Optimized aggregation pipelines for role and permission data
    - Support for advanced permission scenarios
    """
    
    @staticmethod
    def build_effective_permissions_pipeline(
        user_id: str,
        context: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Build pipeline for getting effective permissions for a user in a specific context.
        
        Args:
            user_id: User's payroll ID
            context: Optional context dictionary with business_id, venue_id, etc.
            
        Returns:
            List[Dict]: Aggregation pipeline
        """
        builder = AggregationBuilder()
        
        # Build match query for role assignments
        match_query = {"user_id": user_id, "status": "active"}
        
        # Add context filters if provided
        if context:
            if context.get('business_id'):
                match_query["context.business_id"] = context['business_id']
            
            if context.get('venue_id'):
                match_query["context.venue_id"] = context['venue_id']
            
            if context.get('work_area_id'):
                match_query["context.work_area_id"] = context['work_area_id']
        
        # Start with role assignments
        builder.match(match_query)
        
        # Lookup roles to get permissions
        builder.lookup(
            from_collection="business_roles",
            local_field="role_id",
            foreign_field="role_id",
            as_field="role"
        )
        
        # Unwind role array
        builder.unwind("$role", preserve_null_and_empty=True)
        
        # Add calculated fields for role precedence
        builder.add_fields({
            "role_precedence": {
                "$cond": [
                    {"$eq": ["$role.role_name", "super_admin"]},
                    100,
                    {"$cond": [
                        {"$eq": ["$role.role_name", "admin"]},
                        90,
                        {"$cond": [
                            {"$eq": ["$role.role_name", "manager"]},
                            80,
                            {"$cond": [
                                {"$eq": ["$role.role_name", "supervisor"]},
                                70,
                                {"$cond": [
                                    {"$eq": ["$role.role_name", "staff"]},
                                    60,
                                    50  # Default for other roles
                                ]}
                            ]}
                        ]}
                    ]}
                ]
            }
        })
        
        # Unwind permissions array
        builder.unwind("$role.permissions", preserve_null_and_empty=True)
        
        # Group by permission name to get highest precedence for each permission
        builder.group({
            "_id": "$role.permissions.name",
            "permission": {"$first": "$role.permissions"},
            "context": {"$first": "$context"},
            "role_precedence": {"$max": "$role_precedence"},
            "role_id": {"$first": "$role_id"},
            "overrides": {"$first": "$overrides"}
        })
        
        # Reshape to final output
        builder.project({
            "_id": 0,
            "name": "$_id",
            "permission": 1,
            "context": 1,
            "role_id": 1,
            "effective_value": {
                "$cond": [
                    {"$ifNull": ["$overrides", False]},
                    "$overrides.value",
                    "$permission.value"
                ]
            }
        })
        
        return builder.build()
    
    @staticmethod
    def build_permission_check_pipeline(
        user_id: str,
        permission_name: str,
        context: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Build pipeline for checking a specific permission for a user.
        
        Args:
            user_id: User's payroll ID
            permission_name: Permission to check
            context: Optional context dictionary
            
        Returns:
            List[Dict]: Aggregation pipeline
        """
        builder = AggregationBuilder()
        
        # Build match query for role assignments
        match_query = {"user_id": user_id, "status": "active"}
        
        # Add context filters if provided
        if context:
            if context.get('business_id'):
                match_query["context.business_id"] = context['business_id']
            
            if context.get('venue_id'):
                match_query["context.venue_id"] = context['venue_id']
            
            if context.get('work_area_id'):
                match_query["context.work_area_id"] = context['work_area_id']
        
        # Start with role assignments
        builder.match(match_query)
        
        # Lookup roles to get permissions
        builder.lookup(
            from_collection="business_roles",
            local_field="role_id",
            foreign_field="role_id",
            as_field="role"
        )
        
        # Unwind role array
        builder.unwind("$role", preserve_null_and_empty=True)
        
        # Filter to the specific permission
        builder.match({
            "$or": [
                {"role.permissions.name": permission_name},
                {"role.permissions.name": "all"}  # Special case for full access
            ]
        })
        
        # Project final result (just need to know if any matching documents exist)
        builder.project({
            "_id": 0,
            "has_permission": {"$literal": true},
            "role_name": "$role.role_name",
            "context": 1
        })
        
        # Limit to one result (we just need to know if it exists)
        builder.limit(1)
        
        return builder.build()
