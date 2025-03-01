# ------------------------------------------------------------
# modules/auth/context_validator.py
# ------------------------------------------------------------
from typing import Dict, Optional, Tuple, List
from datetime import datetime
import logging
from bson import ObjectId
from config import Config
from pymongo.errors import OperationFailure, PyMongoError

logger = logging.getLogger(__name__)

class BusinessValidationError(Exception):
    """Custom exception for business validation errors"""
    def __init__(self, message: str, error_code: str):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

class BusinessContextValidator:
    """
    Validates business context for permission checks and hierarchy management.
    
    This validator ensures proper access control and data integrity for business-related
    operations by validating context hierarchies and relationships between business
    entities, venues, and work areas.
    """
    
    def __init__(self, db):
        """
        Initialize the validator with database connection.
        
        Args:
            db: MongoDB database instance
        """
        self.db = db
        self.required_business_fields = {'business_id', 'status', 'venues'}
        self.required_venue_fields = {'venue_id', 'name', 'status'}
        self.required_work_area_fields = {'work_area_id', 'name', 'status'}

    def validate_business_context(self, context: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate business context and return validation status with error message.
        
        Args:
            context: Dictionary containing business context information
                    (business_id, venue_id, work_area_id)
        
        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str])
        
        Raises:
            BusinessValidationError: If validation fails with specific error code
        """
        try:
            if not context:
                return True, None

            # Validate business ID and format
            business_id = context.get('business_id')
            if not business_id:
                return False, "Missing business_id in context"
            
            if not isinstance(business_id, str) or not business_id.startswith('BUS-'):
                return False, "Invalid business_id format"

            # Validate business exists and is active
            business = self.db[Config.COLLECTION_BUSINESSES].find_one({
                'business_id': business_id
            })
            
            if not business:
                return False, f"Business {business_id} not found"
                
            if not self._validate_business_fields(business):
                return False, f"Invalid business structure for {business_id}"
                
            if business.get('status') != 'active':
                return False, f"Business {business_id} is not active"

            # Validate venue if specified
            venue_id = context.get('venue_id')
            if venue_id:
                if not isinstance(venue_id, str) or not venue_id.startswith('VEN-'):
                    return False, "Invalid venue_id format"
                    
                venue = next(
                    (v for v in business.get('venues', []) 
                     if v['venue_id'] == venue_id and v.get('status') == 'active'),
                    None
                )
                
                if not venue:
                    return False, f"Venue {venue_id} not found in business {business_id}"
                    
                if not self._validate_venue_fields(venue):
                    return False, f"Invalid venue structure for {venue_id}"

                # Validate work area if specified
                work_area_id = context.get('work_area_id')
                if work_area_id:
                    if not isinstance(work_area_id, str) or not work_area_id.startswith('WRK-'):
                        return False, "Invalid work_area_id format"
                        
                    work_area = next(
                        (w for w in venue.get('work_areas', [])
                         if w['work_area_id'] == work_area_id and w.get('status') == 'active'),
                        None
                    )
                    
                    if not work_area:
                        return False, f"Work area {work_area_id} not found in venue {venue_id}"
                        
                    if not self._validate_work_area_fields(work_area):
                        return False, f"Invalid work area structure for {work_area_id}"

            return True, None

        except PyMongoError as e:
            logger.error(f"Database error during business validation: {str(e)}")
            return False, "Database error during validation"
        except Exception as e:
            logger.error(f"Business context validation error: {str(e)}")
            return False, f"Validation error: {str(e)}"

    def _validate_business_fields(self, business: Dict) -> bool:
        """Validate required business fields are present and valid."""
        return all(
            field in business and business[field] is not None
            for field in self.required_business_fields
        )

    def _validate_venue_fields(self, venue: Dict) -> bool:
        """Validate required venue fields are present and valid."""
        return all(
            field in venue and venue[field] is not None
            for field in self.required_venue_fields
        )

    def _validate_work_area_fields(self, work_area: Dict) -> bool:
        """Validate required work area fields are present and valid."""
        return all(
            field in work_area and work_area[field] is not None
            for field in self.required_work_area_fields
        )

    @staticmethod
    def setup_db_indexes(db):
        """
        Set up required database indexes for efficient validation.
        
        Args:
            db: MongoDB database instance
        """
        try:
            # Create indexes for business validation
            db[Config.COLLECTION_BUSINESSES].create_index([("business_id", 1)], unique=True)
            db[Config.COLLECTION_BUSINESSES].create_index([("venues.venue_id", 1)])
            db[Config.COLLECTION_BUSINESSES].create_index([("venues.work_areas.work_area_id", 1)])

            logger.info("Business validation indexes created successfully")
        except Exception as e:
            logger.error(f"Error creating business validation indexes: {str(e)}")
            raise
