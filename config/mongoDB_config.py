"""
MongoDB configuration and connection management module.

This module provides a centralized configuration for MongoDB connections,
collection definitions, schemas, and utility functions for database operations.
"""
from pymongo import MongoClient, ASCENDING, DESCENDING, IndexModel
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, DuplicateKeyError
import logging
import os
from datetime import datetime
from decimal import Decimal
from bson.objectid import ObjectId
from dotenv import load_dotenv
import uuid

# Load environment variables
load_dotenv()

# MongoDB Connection Settings
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
MONGO_DBNAME = os.getenv('MONGO_DBNAME', 'MyCookBook')
MONGO_CONNECT_TIMEOUT = int(os.getenv('MONGO_CONNECT_TIMEOUT', 5000))
MONGO_MAX_POOL_SIZE = int(os.getenv('MONGO_MAX_POOL_SIZE', 100))
MONGO_SERVER_SELECTION_TIMEOUT = int(os.getenv('MONGO_SERVER_SELECTION_TIMEOUT', 10000))

# Configure logging
logger = logging.getLogger(__name__)

# Collection Names
COLLECTION_BUSINESS_ENTITIES = 'business_entities'
COLLECTION_BUSINESS_VENUES = 'business_venues'
COLLECTION_BUSINESS_USERS = 'business_users'
COLLECTION_ROLE_IDS = 'role_ids'
COLLECTION_ALLERGENS = 'allergens'
COLLECTION_EMPLOYMENT_ROLES = 'employment_roles'
COLLECTION_MEATSPACE = 'meatspace'
COLLECTION_PRODUCT_LIST = 'product_list'
COLLECTION_USER_NOTES = 'user_notes'

# Collection index definitions
COLLECTION_INDEXES = {
    COLLECTION_BUSINESS_ENTITIES: [
        IndexModel([("company_id", ASCENDING)], unique=True),
        IndexModel([("venues.venue_id", ASCENDING)])
    ],
    COLLECTION_BUSINESS_VENUES: [
        IndexModel([("venue_id", ASCENDING)], unique=True),
        IndexModel([("company_id", ASCENDING)]),
        IndexModel([("workareas.work_area_id", ASCENDING)]),
        IndexModel([("workareas.employees.linking_id", ASCENDING)])
    ],
    COLLECTION_BUSINESS_USERS: [
        IndexModel([("payroll_id", ASCENDING)], unique=True),
        IndexModel([("linking_id", ASCENDING)], unique=True),
        IndexModel([("company_id", ASCENDING)]),
        IndexModel([("venue_id", ASCENDING)]),
        IndexModel([("work_area_id", ASCENDING)]),
        IndexModel([("role_id", ASCENDING)]),
        IndexModel([("work_email", ASCENDING)]),
        IndexModel([("employment_details.hired_date", ASCENDING)])
    ],
    COLLECTION_ROLE_IDS: [
        IndexModel([("_id", ASCENDING)], unique=True)
    ],
    COLLECTION_ALLERGENS: [
        IndexModel([("ingredient", ASCENDING)], unique=True),
        IndexModel([("severity", ASCENDING)])
    ],
    COLLECTION_EMPLOYMENT_ROLES: [
        IndexModel([("role_id", ASCENDING)], unique=True),
        IndexModel([("class", ASCENDING)])
    ],
    COLLECTION_MEATSPACE: [
        IndexModel([("name", ASCENDING)]),
        IndexModel([("muscleGroup", ASCENDING)])
    ],
    COLLECTION_PRODUCT_LIST: [
        IndexModel([("INGREDIENT", ASCENDING)]),
        IndexModel([("SUPPLIER", ASCENDING)])
    ],
    COLLECTION_USER_NOTES: [
        IndexModel([("id", ASCENDING)], unique=True),
        IndexModel([("created_at", DESCENDING)])
    ]
}

def init_mongo():
    """
    Initialize MongoDB connection with error handling and connection testing.
    
    Returns:
        MongoClient: MongoDB client if successful, None if connection fails
    """
    try:
        # Create MongoDB client with robust configuration
        client = MongoClient(
            MONGO_URI, 
            serverSelectionTimeoutMS=MONGO_SERVER_SELECTION_TIMEOUT,
            maxPoolSize=MONGO_MAX_POOL_SIZE,
            connectTimeoutMS=MONGO_CONNECT_TIMEOUT,
            retryWrites=True,
            w='majority'
        )
        
        # Test connection
        client.admin.command('ping')
        logger.info(f"Successfully connected to MongoDB at {MONGO_URI}")
        
        # Initialize database and collections if they don't exist
        db = client[MONGO_DBNAME]
        
        # Create missing collections and setup indexes
        for collection_name, indexes in COLLECTION_INDEXES.items():
            if collection_name not in db.list_collection_names():
                db.create_collection(collection_name)
                logger.info(f"Created collection: {collection_name}")
            
            # Create or update indexes
            created_indexes = db[collection_name].create_indexes(indexes)
            logger.info(f"Created {len(created_indexes)} indexes for collection {collection_name}")
        
        return client
        
    except ConnectionFailure as e:
        logger.error(f"MongoDB Connection Error: {str(e)}")
        return None
    except ServerSelectionTimeoutError as e:
        logger.error(f"MongoDB Server Selection Timeout: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected MongoDB Error: {str(e)}")
        return None

def get_db():
    """
    Get MongoDB database instance.
    
    Returns:
        Database: MongoDB database instance if connection successful, None otherwise
    """
    client = init_mongo()
    if client:
        return client[MONGO_DBNAME]
    return None

def get_collection(collection_name):
    """
    Get a specific MongoDB collection.
    
    Args:
        collection_name (str): Name of the collection to retrieve
        
    Returns:
        Collection: MongoDB collection object if successful, None otherwise
    """
    db = get_db()
    if db and collection_name in db.list_collection_names():
        return db[collection_name]
    logger.error(f"Collection '{collection_name}' not found")
    return None

def close_connection(client):
    """
    Close MongoDB connection safely.
    
    Args:
        client (MongoClient): MongoDB client to close
    """
    if client:
        try:
            client.close()
            logger.info("MongoDB connection closed")
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {str(e)}")

def test_connection():
    """
    Test MongoDB connection and return status.
    
    Returns:
        tuple: (bool, str) indicating success/failure and message
    """
    try:
        client = init_mongo()
        if client:
            db = client[MONGO_DBNAME]
            collections = db.list_collection_names()
            return True, f"Connected to MongoDB. Available collections: {collections}"
        return False, "Failed to initialize MongoDB connection"
    except Exception as e:
        return False, f"MongoDB Connection Test Failed: {str(e)}"

# =============================
# Business Entities Operations
# =============================

def get_business_entity(company_id):
    """
    Get a business entity by company ID.
    
    Args:
        company_id (str): Company ID to retrieve
        
    Returns:
        dict: Business entity document or None if not found
    """
    try:
        collection = get_collection(COLLECTION_BUSINESS_ENTITIES)
        if collection:
            return collection.find_one({"company_id": company_id})
        return None
    except Exception as e:
        logger.error(f"Error fetching business entity with ID {company_id}: {str(e)}")
        return None

def get_venues_for_company(company_id):
    """
    Get all venues for a specific company.
    
    Args:
        company_id (str): Company ID to retrieve venues for
        
    Returns:
        list: List of venue documents or empty list if none found
    """
    try:
        business_entity = get_business_entity(company_id)
        if business_entity and "venues" in business_entity:
            return business_entity["venues"]
        return []
    except Exception as e:
        logger.error(f"Error fetching venues for company ID {company_id}: {str(e)}")
        return []

# =============================
# Business Venues Operations
# =============================

def get_venue_details(venue_id):
    """
    Get details for a specific venue.
    
    Args:
        venue_id (str): Venue ID to retrieve
        
    Returns:
        dict: Venue document or None if not found
    """
    try:
        collection = get_collection(COLLECTION_BUSINESS_VENUES)
        if collection:
            return collection.find_one({"venue_id": venue_id})
        return None
    except Exception as e:
        logger.error(f"Error fetching venue with ID {venue_id}: {str(e)}")
        return None

def get_employees_for_venue(venue_id):
    """
    Get all employees for a specific venue.
    
    Args:
        venue_id (str): Venue ID to retrieve employees for
        
    Returns:
        list: List of employee documents or empty list if none found
    """
    try:
        venue = get_venue_details(venue_id)
        employees = []
        
        if venue and "workareas" in venue:
            for workarea in venue["workareas"]:
                if "employees" in workarea:
                    for employee in workarea["employees"]:
                        employee["work_area_id"] = workarea["work_area_id"]
                        employee["work_area_name"] = workarea["work_area_name"]
                        employees.append(employee)
        return employees
    except Exception as e:
        logger.error(f"Error fetching employees for venue ID {venue_id}: {str(e)}")
        return []

def get_workareas_for_venue(venue_id):
    """
    Get all work areas for a specific venue.
    
    Args:
        venue_id (str): Venue ID to retrieve work areas for
        
    Returns:
        list: List of work area documents or empty list if none found
    """
    try:
        venue = get_venue_details(venue_id)
        if venue and "workareas" in venue:
            return venue["workareas"]
        return []
    except Exception as e:
        logger.error(f"Error fetching work areas for venue ID {venue_id}: {str(e)}")
        return []

# =============================
# Business Users Operations
# =============================

def get_user_by_payroll_id(payroll_id):
    """
    Find a user by their payroll ID.
    
    Args:
        payroll_id (str): Payroll ID to search for
        
    Returns:
        dict: User document or None if not found
    """
    try:
        collection = get_collection(COLLECTION_BUSINESS_USERS)
        if collection:
            return collection.find_one({"payroll_id": payroll_id})
        return None
    except Exception as e:
        logger.error(f"Error finding user by payroll ID {payroll_id}: {str(e)}")
        return None

def get_user_by_linking_id(linking_id):
    """
    Find a user by their linking ID.
    
    Args:
        linking_id (str): Linking ID to search for
        
    Returns:
        dict: User document or None if not found
    """
    try:
        collection = get_collection(COLLECTION_BUSINESS_USERS)
        if collection:
            return collection.find_one({"linking_id": linking_id})
        return None
    except Exception as e:
        logger.error(f"Error finding user by linking ID {linking_id}: {str(e)}")
        return None

def get_users_by_venue(venue_id):
    """
    Get all users for a specific venue.
    
    Args:
        venue_id (str): Venue ID to retrieve users for
        
    Returns:
        list: List of user documents or empty list if none found
    """
    try:
        collection = get_collection(COLLECTION_BUSINESS_USERS)
        if collection:
            return list(collection.find({"venue_id": venue_id}))
        return []
    except Exception as e:
        logger.error(f"Error fetching users for venue ID {venue_id}: {str(e)}")
        return []

def get_users_by_work_area(work_area_id):
    """
    Get all users for a specific work area.
    
    Args:
        work_area_id (str): Work area ID to retrieve users for
        
    Returns:
        list: List of user documents or empty list if none found
    """
    try:
        collection = get_collection(COLLECTION_BUSINESS_USERS)
        if collection:
            return list(collection.find({"work_area_id": work_area_id}))
        return []
    except Exception as e:
        logger.error(f"Error fetching users for work area ID {work_area_id}: {str(e)}")
        return []

def get_users_by_role(role_id):
    """
    Get all users with a specific role.
    
    Args:
        role_id (str): Role ID to retrieve users for
        
    Returns:
        list: List of user documents or empty list if none found
    """
    try:
        collection = get_collection(COLLECTION_BUSINESS_USERS)
        if collection:
            return list(collection.find({"role_id": role_id}))
        return []
    except Exception as e:
        logger.error(f"Error fetching users for role ID {role_id}: {str(e)}")
        return []

# =============================
# Role Operations
# =============================

def get_role_details(role_id):
    """
    Get details for a specific role.
    
    Args:
        role_id (str): Role ID to retrieve details for (e.g., 'BOH-EXE-207')
        
    Returns:
        dict: Role details or None if not found
    """
    try:
        if not role_id or len(role_id) < 3:
            return None
            
        # Extract department code (e.g., "BOH" from "BOH-EXE-207")
        dept_code = role_id.split('-')[0].lower()
        
        # Map department code to collection ID
        dept_mapping = {
            'adm': 'admin_roles',
            'boh': 'boh_roles',
            'foh': 'foh_roles',
            'gsh': 'gsh_roles'
        }
        
        category = dept_mapping.get(dept_code)
        if not category:
            return None
            
        # Find the role collection
        collection = get_collection(COLLECTION_ROLE_IDS)
        if not collection:
            return None
            
        # Find the document for this category
        category_doc = collection.find_one({"_id": category})
        if not category_doc:
            return None
            
        # Search all role types for matching role ID
        for role_type in ['Dept Manager', 'Employee', 'Executive Management', 
                         'Management', 'Senior Management', 'Sub-Dept Manager']:
            if role_type in category_doc:
                for role in category_doc[role_type]:
                    if role.get('role_id') == role_id:
                        return {
                            'role_id': role_id,
                            'role_name': role.get('role'),
                            'role_type': role_type,
                            'department': dept_code.upper()
                        }
        return None
    except Exception as e:
        logger.error(f"Error finding role info for ID {role_id}: {str(e)}")
        return None

def get_employment_role_details(role_id):
    """
    Get detailed employment role information from the employment_roles collection.
    
    Args:
        role_id (str): Role ID to retrieve details for
        
    Returns:
        dict: Role document or None if not found
    """
    try:
        collection = get_collection(COLLECTION_EMPLOYMENT_ROLES)
        if collection:
            return collection.find_one({"role_id": role_id})
        return None
    except Exception as e:
        logger.error(f"Error fetching employment role details for role ID {role_id}: {str(e)}")
        return None

# =============================
# Allergen Operations
# =============================

def get_allergen_by_name(ingredient):
    """
    Get allergen information by ingredient name.
    
    Args:
        ingredient (str): Ingredient name to search for
        
    Returns:
        dict: Allergen document or None if not found
    """
    try:
        collection = get_collection(COLLECTION_ALLERGENS)
        if collection:
            return collection.find_one({"ingredient": ingredient})
        return None
    except Exception as e:
        logger.error(f"Error fetching allergen information for {ingredient}: {str(e)}")
        return None

def get_allergens_by_severity(severity):
    """
    Get allergens by severity level.
    
    Args:
        severity (str): Severity level (HIGH, MEDIUM, LOW, CRITICAL)
        
    Returns:
        list: List of allergen documents or empty list if none found
    """
    try:
        collection = get_collection(COLLECTION_ALLERGENS)
        if collection:
            # Normalize severity to uppercase for case-insensitive comparison
            severity = severity.upper()
            return list(collection.find({"severity": severity}))
        return []
    except Exception as e:
        logger.error(f"Error fetching allergens with severity {severity}: {str(e)}")
        return []

def search_allergens(query):
    """
    Search for allergens by ingredient name.
    
    Args:
        query (str): Search query for ingredient name
        
    Returns:
        list: List of matching allergen documents or empty list if none found
    """
    try:
        collection = get_collection(COLLECTION_ALLERGENS)
        if collection:
            # Case-insensitive search using regex
            return list(collection.find({"ingredient": {"$regex": query, "$options": "i"}}))
        return []
    except Exception as e:
        logger.error(f"Error searching allergens with query {query}: {str(e)}")
        return []

# =============================
# Meatspace Operations
# =============================

def get_beef_cut_by_name(name):
    """
    Get a beef cut by name.
    
    Args:
        name (str): Name of the beef cut
        
    Returns:
        dict: Beef cut document or None if not found
    """
    try:
        collection = get_collection(COLLECTION_MEATSPACE)
        if collection:
            return collection.find_one({"name": name})
        return None
    except Exception as e:
        logger.error(f"Error fetching beef cut with name {name}: {str(e)}")
        return None

def get_beef_cuts_by_muscle_group(muscle_group):
    """
    Get beef cuts by muscle group.
    
    Args:
        muscle_group (str): Muscle group to search for
        
    Returns:
        list: List of beef cut documents or empty list if none found
    """
    try:
        collection = get_collection(COLLECTION_MEATSPACE)
        if collection:
            return list(collection.find({"muscleGroup": muscle_group}))
        return []
    except Exception as e:
        logger.error(f"Error fetching beef cuts for muscle group {muscle_group}: {str(e)}")
        return []

def search_beef_cuts(query):
    """
    Search for beef cuts by name.
    
    Args:
        query (str): Search query for beef cut name
        
    Returns:
        list: List of matching beef cut documents or empty list if none found
    """
    try:
        collection = get_collection(COLLECTION_MEATSPACE)
        if collection:
            # Case-insensitive search using regex
            return list(collection.find({"name": {"$regex": query, "$options": "i"}}))
        return []
    except Exception as e:
        logger.error(f"Error searching beef cuts with query {query}: {str(e)}")
        return []

# =============================
# Product List Operations
# =============================

def get_product_by_ingredient(ingredient):
    """
    Get product information by ingredient name.
    
    Args:
        ingredient (str): Ingredient name to search for
        
    Returns:
        dict: Product document or None if not found
    """
    try:
        collection = get_collection(COLLECTION_PRODUCT_LIST)
        if collection:
            return collection.find_one({"INGREDIENT": ingredient})
        return None
    except Exception as e:
        logger.error(f"Error fetching product with ingredient {ingredient}: {str(e)}")
        return None

def get_products_by_supplier(supplier):
    """
    Get products by supplier.
    
    Args:
        supplier (str): Supplier name to search for
        
    Returns:
        list: List of product documents or empty list if none found
    """
    try:
        collection = get_collection(COLLECTION_PRODUCT_LIST)
        if collection:
            return list(collection.find({"SUPPLIER": supplier}))
        return []
    except Exception as e:
        logger.error(f"Error fetching products from supplier {supplier}: {str(e)}")
        return []

def search_products(query):
    """
    Search for products by ingredient name.
    
    Args:
        query (str): Search query for ingredient name
        
    Returns:
        list: List of matching product documents or empty list if none found
    """
    try:
        collection = get_collection(COLLECTION_PRODUCT_LIST)
        if collection:
            # Case-insensitive search using regex
            return list(collection.find({"INGREDIENT": {"$regex": query, "$options": "i"}}))
        return []
    except Exception as e:
        logger.error(f"Error searching products with query {query}: {str(e)}")
        return []

# =============================
# User Notes Operations
# =============================

def get_user_note(note_id):
    """
    Get a user note by ID.
    
    Args:
        note_id (str): Note ID to retrieve
        
    Returns:
        dict: Note document or None if not found
    """
    try:
        collection = get_collection(COLLECTION_USER_NOTES)
        if collection:
            return collection.find_one({"id": note_id})
        return None
    except Exception as e:
        logger.error(f"Error fetching note with ID {note_id}: {str(e)}")
        return None

def get_all_user_notes():
    """
    Get all user notes sorted by creation date (newest first).
    
    Returns:
        list: List of note documents or empty list if none found
    """
    try:
        collection = get_collection(COLLECTION_USER_NOTES)
        if collection:
            return list(collection.find().sort("created_at", DESCENDING))
        return []
    except Exception as e:
        logger.error(f"Error fetching all notes: {str(e)}")
        return []

def create_user_note(title, items=None, labels=None):
    """
    Create a new user note.
    
    Args:
        title (str): Note title
        items (list, optional): List of checklist items
        labels (list, optional): List of labels
        
    Returns:
        dict: Created note document or None if creation failed
    """
    try:
        collection = get_collection(COLLECTION_USER_NOTES)
        if not collection:
            return None
            
        note_id = str(uuid.uuid4())
        created_at = datetime.utcnow().isoformat()
        
        note = {
            "title": title,
            "items": items or [],
            "labels": labels or [],
            "id": note_id,
            "created_at": created_at
        }
        
        result = collection.insert_one(note)
        if result.inserted_id:
            return note
        return None
    except Exception as e:
        logger.error(f"Error creating note: {str(e)}")
        return None

def update_user_note(note_id, title=None, items=None, labels=None):
    """
    Update an existing user note.
    
    Args:
        note_id (str): Note ID to update
        title (str, optional): New note title
        items (list, optional): New list of checklist items
        labels (list, optional): New list of labels
        
    Returns:
        bool: True if update successful, False otherwise
    """
    try:
        collection = get_collection(COLLECTION_USER_NOTES)
        if not collection:
            return False
            
        update_fields = {}
        if title is not None:
            update_fields["title"] = title
        if items is not None:
            update_fields["items"] = items
        if labels is not None:
            update_fields["labels"] = labels
            
        if not update_fields:
            return False
            
        result = collection.update_one({"id": note_id}, {"$set": update_fields})
        return result.modified_count > 0
    except Exception as e:
        logger.error(f"Error updating note with ID {note_id}: {str(e)}")
        return False

def delete_user_note(note_id):
    """
    Delete a user note.
    
    Args:
        note_id (str): Note ID to delete
        
    Returns:
        bool: True if deletion successful, False otherwise
    """
    try:
        collection = get_collection(COLLECTION_USER_NOTES)
        if not collection:
            return False
            
        result = collection.delete_one({"id": note_id})
        return result.deleted_count > 0
    except Exception as e:
        logger.error(f"Error deleting note with ID {note_id}: {str(e)}")
        return False

# Initialize MongoDB connection
MONGO_CLIENT = init_mongo()

# Export collections configuration for external use
COLLECTIONS = {
    'business_entities': COLLECTION_BUSINESS_ENTITIES,
    'business_venues': COLLECTION_BUSINESS_VENUES,
    'business_users': COLLECTION_BUSINESS_USERS,
    'role_ids': COLLECTION_ROLE_IDS,
    'allergens': COLLECTION_ALLERGENS,
    'employment_roles': COLLECTION_EMPLOYMENT_ROLES,
    'meatspace': COLLECTION_MEATSPACE,
    'product_list': COLLECTION_PRODUCT_LIST,
    'user_notes': COLLECTION_USER_NOTES
}
