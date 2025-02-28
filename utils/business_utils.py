# utils/business_utils.py (Final Validated Version)
from datetime import datetime
import uuid
import logging
from config.base_config import Config
from pymongo.errors import PyMongoError

logger = logging.getLogger(__name__)

# 1. Business Core Functions ==================================================
def lookup_business(db, business_id):
    """Full business entity retrieval with error handling"""
    try:
        result = db[Config.COLLECTION_BUSINESSES].find_one(
            {'business_id': business_id},
            {'_id': 0, 'venues': 1, 'admin_user_id': 1}
        )
        if result:
            logger.debug(f"Found business: {business_id}")
            return result
        logger.warning(f"Business not found: {business_id}")
        return None
    except PyMongoError as e:
        logger.error(f"Business lookup failed: {str(e)}")
        return None

def create_business(db, admin_user_id, business_data):
    """Business creation with validation"""
    try:
        business_id = f"BUS-{uuid.uuid4().hex[:8].upper()}"
        business_doc = {
            'business_id': business_id,
            'admin_user_id': admin_user_id,
            'name': business_data['name'],
            'venue_type': business_data['venue_type'],
            'status': 'setup_in_progress',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'venues': []
        }
        
        insert_result = db[Config.COLLECTION_BUSINESSES].insert_one(business_doc)
        if insert_result.inserted_id:
            logger.info(f"Created business: {business_id}")
            return business_doc
        return None
    except PyMongoError as e:
        logger.error(f"Business creation error: {str(e)}")
        return None

# 2. Venue Management ========================================================
def lookup_venue(db, venue_id):
    """Complete venue lookup with parent business context"""
    try:
        result = db[Config.COLLECTION_BUSINESSES].find_one(
            {'venues.venue_id': venue_id},
            {'company_id': 1, 'venues.$': 1}  # Changed from business_id to company_id
        )
        if result and result.get('venues'):
            logger.debug(f"Found venue: {venue_id}")
            return {
                # Map to expected key name while using actual schema field
                'business_id': result['company_id'],  # Key fix
                'venue': result['venues'][0]
            }
        logger.warning(f"Venue not found: {venue_id}")
        return None
    except PyMongoError as e:
        logger.error(f"Venue lookup error: {str(e)}")
        return None

def add_venue_to_business(db, business_id, venue_data):
    """Atomic venue addition with error handling"""
    try:
        venue_id = f"VEN-{uuid.uuid4().hex[:8].upper()}"
        venue_doc = {
            'venue_id': venue_id,
            'name': venue_data['name'],
            'address': venue_data.get('address'),
            'contact': venue_data.get('contact'),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'work_areas': []
        }

        result = db[Config.COLLECTION_BUSINESSES].update_one(
            {'business_id': business_id},
            {
                '$push': {'venues': venue_doc},
                '$set': {'updated_at': datetime.utcnow()}
            }
        )
        if result.modified_count > 0:
            logger.info(f"Added venue {venue_id} to business {business_id}")
            return venue_doc
        logger.warning(f"Business not found: {business_id}")
        return None
    except PyMongoError as e:
        logger.error(f"Venue addition failed: {str(e)}")
        return None

# 3. Work Area Management ====================================================
def lookup_work_area(db, work_area_id):
    """Full work area lookup with aggregation"""
    try:
        pipeline = [
            {'$unwind': '$venues'},
            {'$unwind': '$venues.work_areas'},
            {'$match': {'venues.work_areas.work_area_id': work_area_id}},
            {'$project': {
                'business_id': 1,
                'venue_id': '$venues.venue_id',
                'venue_name': '$venues.name',
                'work_area': '$venues.work_areas'
            }}
        ]
        result = list(db[Config.COLLECTION_BUSINESSES].aggregate(pipeline))
        return result[0] if result else None
    except PyMongoError as e:
        logger.error(f"Work area lookup error: {str(e)}")
        return None

def add_work_area_to_venue(db, business_id, venue_id, work_area_data):
    """Work area creation with nested updates"""
    try:
        work_area_id = f"WRK-{uuid.uuid4().hex[:8].upper()}"
        work_area_doc = {
            'work_area_id': work_area_id,
            'name': work_area_data['name'],
            'description': work_area_data.get('description'),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'employees': []
        }

        result = db[Config.COLLECTION_BUSINESSES].update_one(
            {'business_id': business_id, 'venues.venue_id': venue_id},
            {
                '$push': {'venues.$.work_areas': work_area_doc},
                '$set': {'updated_at': datetime.utcnow()}
            }
        )
        if result.modified_count > 0:
            logger.info(f"Added work area {work_area_id} to venue {venue_id}")
            return work_area_doc
        logger.warning(f"Venue {venue_id} not found in business {business_id}")
        return None
    except PyMongoError as e:
        logger.error(f"Work area creation failed: {str(e)}")
        return None

# 4. User Assignments ========================================================
def assign_user_to_business(db, business_id, user_id, role_name='employee'):
    """Complete business user assignment"""
    try:
        role_doc = db[Config.COLLECTION_BUSINESS_ROLES].find_one({'role_name': role_name})
        if not role_doc:
            logger.error(f"Role not found: {role_name}")
            return None

        business_user_doc = {
            'business_id': business_id,
            'user_id': user_id,
            'role_name': role_name,
            'permissions': role_doc['permissions'],
            'assigned_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'status': 'active'
        }

        result = db[Config.COLLECTION_BUSINESS_USERS].update_one(
            {'business_id': business_id, 'user_id': user_id},
            {'$set': business_user_doc},
            upsert=True
        )
        logger.info(f"Assigned user {user_id} to business {business_id}")
        return business_user_doc
    except PyMongoError as e:
        logger.error(f"Business assignment failed: {str(e)}")
        return None

def assign_user_to_work_area(db, business_id, venue_id, work_area_id, user_id, role_data):
    """Atomic work area assignment with array filters"""
    try:
        employee_doc = {
            'user_id': user_id,
            'role': role_data.get('role', 'staff'),
            'assigned_at': datetime.utcnow(),
            'status': 'active'
        }

        result = db[Config.COLLECTION_BUSINESSES].update_one(
            {
                'business_id': business_id,
                'venues.venue_id': venue_id,
                'venues.work_areas.work_area_id': work_area_id
            },
            {
                '$push': {'venues.$[venue].work_areas.$[workArea].employees': employee_doc},
                '$set': {'updated_at': datetime.utcnow()}
            },
            array_filters=[
                {'venue.venue_id': venue_id},
                {'workArea.work_area_id': work_area_id}
            ]
        )
        if result.modified_count > 0:
            logger.info(f"Assigned user {user_id} to work area {work_area_id}")
            return True
        logger.warning(f"Assignment target not found: {work_area_id}")
        return False
    except PyMongoError as e:
        logger.error(f"Work area assignment failed: {str(e)}")
        return False

# 5. Business Operations =====================================================
def get_business_hierarchy(db, business_id):
    """Complete hierarchy aggregation"""
    try:
        pipeline = [
            {'$match': {'business_id': business_id}},
            {'$lookup': {
                'from': Config.COLLECTION_BUSINESS_USERS,
                'localField': 'business_id',
                'foreignField': 'business_id',
                'as': 'employees'
            }},
            {'$unwind': '$venues'},
            {'$unwind': '$venues.work_areas'},
            {'$project': {
                'business_id': 1,
                'name': 1,
                'venue': '$venues',
                'work_area': '$venues.work_areas',
                'employees': 1
            }}
        ]
        return list(db[Config.COLLECTION_BUSINESSES].aggregate(pipeline))
    except PyMongoError as e:
        logger.error(f"Hierarchy fetch failed: {str(e)}")
        return []

def update_business_status(db, business_id, new_status):
    """Status update with validation"""
    try:
        result = db[Config.COLLECTION_BUSINESSES].update_one(
            {'business_id': business_id},
            {'$set': {'status': new_status, 'updated_at': datetime.utcnow()}}
        )
        if result.modified_count > 0:
            logger.info(f"Updated {business_id} status to {new_status}")
            return True
        logger.warning(f"Business not found: {business_id}")
        return False
    except PyMongoError as e:
        logger.error(f"Status update failed: {str(e)}")
        return False

def validate_business_structure(db, business_id):
    """Comprehensive structure validation"""
    try:
        business = lookup_business(db, business_id)
        issues = []
        
        if not business:
            return False, ["Business not found"]

        required_fields = ['name', 'admin_user_id', 'venue_type', 'venues']
        for field in required_fields:
            if field not in business:
                issues.append(f"Missing required field: {field}")

        if not isinstance(business.get('venues'), list):
            issues.append("Venues must be a list")
        else:
            for venue in business['venues']:
                if 'venue_id' not in venue:
                    issues.append(f"Venue missing ID: {venue.get('name', 'Unnamed')}")
                if 'work_areas' not in venue:
                    issues.append(f"Venue missing work areas: {venue.get('venue_id', 'No ID')}")

        return (len(issues) == 0, issues)
    except PyMongoError as e:
        logger.error(f"Validation failed: {str(e)}")
        return False, [f"Validation error: {str(e)}"]
