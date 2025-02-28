# ------------------------------#
#       utils/db_utils.py       #
# ------------------------------#
from datetime import datetime
import logging
from typing import Dict, List, Optional, Union, Any
from bson import ObjectId

logger = logging.getLogger(__name__)

def safe_object_id(id_str: str) -> Optional[ObjectId]:
    """
    Safely convert string to ObjectId
    """
    try:
        return ObjectId(id_str) if id_str else None
    except Exception as e:
        logger.error(f"Error converting to ObjectId: {str(e)}")
        return None

def format_mongo_doc(doc: Dict) -> Dict:
    """
    Format MongoDB document for JSON response
    """
    if not doc:
        return {}
        
    formatted = dict(doc)
    
    # Convert ObjectId to string
    if '_id' in formatted:
        formatted['_id'] = str(formatted['_id'])
        
    # Convert datetime objects to ISO format
    for key, value in formatted.items():
        if isinstance(value, datetime):
            formatted[key] = value.isoformat()
            
    return formatted

def create_mongo_query(filters: Dict) -> Dict:
    """
    Create MongoDB query from filters
    """
    query = {}
    
    for key, value in filters.items():
        if value is None:
            continue
            
        if isinstance(value, str) and key not in ['_id', 'id']:
            query[key] = {'$regex': f'^{value}$', '$options': 'i'}
        else:
            query[key] = value
            
    return query

def handle_mongo_error(error: Exception, context: str) -> Dict:
    """
    Handle MongoDB errors and return appropriate response
    """
    error_msg = str(error)
    logger.error(f"MongoDB Error in {context}: {error_msg}")
    
    if "duplicate key error" in error_msg.lower():
        return {
            "success": False,
            "message": "A record with this identifier already exists",
            "error_code": "DUPLICATE_KEY"
        }
        
    return {
        "success": False,
        "message": "An error occurred while processing your request",
        "error_code": "DATABASE_ERROR"
    }

def sanitize_mongo_query(query: Dict) -> Dict:
    """
    Sanitize MongoDB query to prevent injection
    """
    sanitized = {}
    
    for key, value in query.items():
        # Prevent NoSQL injection by checking types
        if isinstance(value, dict):
            sanitized[key] = sanitize_mongo_query(value)
        elif isinstance(value, (str, int, float, bool, ObjectId)):
            sanitized[key] = value
        elif isinstance(value, list):
            sanitized[key] = [v for v in value if isinstance(v, (str, int, float, bool, ObjectId))]
            
    return sanitized

def build_aggregation_pipeline(
    match: Optional[Dict] = None,
    project: Optional[Dict] = None,
    sort: Optional[Dict] = None,
    limit: Optional[int] = None,
    skip: Optional[int] = None
) -> List[Dict]:
    """
    Build MongoDB aggregation pipeline
    """
    pipeline = []
    
    if match:
        pipeline.append({'$match': sanitize_mongo_query(match)})
        
    if project:
        pipeline.append({'$project': project})
        
    if sort:
        pipeline.append({'$sort': sort})
        
    if skip:
        pipeline.append({'$skip': skip})
        
    if limit:
        pipeline.append({'$limit': limit})
        
    return pipeline

def update_timestamp_fields(doc: Dict, is_new: bool = False) -> Dict:
    """
    Update timestamp fields in document
    """
    now = datetime.utcnow()
    doc['updated_at'] = now
    
    if is_new:
        doc['created_at'] = now
        
    return doc

def get_collection_stats(db, collection_name: str) -> Dict:
    """
    Get collection statistics
    """
    try:
        stats = db.command('collStats', collection_name)
        return {
            'count': stats.get('count', 0),
            'size': stats.get('size', 0),
            'avg_obj_size': stats.get('avgObjSize', 0),
            'storage_size': stats.get('storageSize', 0),
            'indexed': stats.get('totalIndexSize', 0)
        }
    except Exception as e:
        logger.error(f"Error getting collection stats: {str(e)}")
        return {}

def ensure_indexes(db, collection_name: str, indexes: List[Dict]) -> None:
    """
    Ensure indexes exist on collection
    """
    try:
        collection = db[collection_name]
        existing_indexes = collection.list_indexes()
        existing_index_names = [idx.get('name') for idx in existing_indexes]
        
        for index in indexes:
            name = index.get('name')
            if name and name not in existing_index_names:
                collection.create_index(**index)
                logger.info(f"Created index {name} on {collection_name}")
                
    except Exception as e:
        logger.error(f"Error ensuring indexes: {str(e)}")

def bulk_write_operations(
    db,
    collection_name: str,
    operations: List[Dict],
    ordered: bool = False
) -> Dict:
    """
    Execute bulk write operations
    """
    try:
        result = db[collection_name].bulk_write(operations, ordered=ordered)
        return {
            'success': True,
            'inserted': result.inserted_count,
            'modified': result.modified_count,
            'deleted': result.deleted_count
        }
    except Exception as e:
        logger.error(f"Bulk write error: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def get_distinct_values(
    db,
    collection_name: str,
    field: str,
    query: Optional[Dict] = None
) -> List:
    """
    Get distinct values for a field
    """
    try:
        query = sanitize_mongo_query(query) if query else {}
        return db[collection_name].distinct(field, query)
    except Exception as e:
        logger.error(f"Error getting distinct values: {str(e)}")
        return []

def execute_transaction(db, operations: List[callable]) -> bool:
    """
    Execute multiple operations in a transaction
    """
    with db.client.start_session() as session:
        try:
            with session.start_transaction():
                for operation in operations:
                    operation(session)
                return True
        except Exception as e:
            logger.error(f"Transaction error: {str(e)}")
            return False
