#-------------------------------------------------------------------------------#
#                          utils/allergens_utils.py                             #
#-------------------------------------------------------------------------------#
from typing import Dict, List, Optional, Union
import logging
from datetime import datetime
from bson import ObjectId

logger = logging.getLogger(__name__)

class AllergenError(Exception):
    """Custom exception for allergen-related errors"""
    def __init__(self, message: str, error_code: str = 'ALLERGEN_ERROR'):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

def lookup_allergen(db, ingredient_name: str) -> Optional[List[Dict]]:
    """
    Look up allergens in the allergens collection using partial matches on the ingredient name.
    Returns allergen data including ingredient name, severity, reaction type, etc.
    
    Args:
        db: MongoDB database instance
        ingredient_name: Name of ingredient to check for allergens
        
    Returns:
        List of allergen documents or None if not found
    """
    try:
        #-------------------------------------------------------------------------------#
        #              Partial match on ingredient field in allergens collection        #
        #-------------------------------------------------------------------------------#
        query = {'ingredient': {'$regex': f'{ingredient_name}', '$options': 'i'}}
        allergens = db.allergens.find(query)
        
        #-------------------------------------------------------------------------------#
        #        Convert MongoDB cursor to list and return the allergen details         #
        #-------------------------------------------------------------------------------#
        allergens_list = list(allergens)
        if allergens_list:
            logger.debug(f"Found allergens for ingredient '{ingredient_name}': {allergens_list}")
            return allergens_list
        logger.debug(f"No allergens found for ingredient: {ingredient_name}")
        return None
    except Exception as e:
        logger.error(f"Error looking up allergen: {str(e)}")
        raise AllergenError(f"Failed to lookup allergen: {str(e)}")

def get_allergen_by_id(db, allergen_id: Union[str, ObjectId]) -> Optional[Dict]:
    """
    Get specific allergen by ID
    
    Args:
        db: MongoDB database instance
        allergen_id: ID of allergen to retrieve
        
    Returns:
        Allergen document or None if not found
    """
    try:
        if isinstance(allergen_id, str):
            allergen_id = ObjectId(allergen_id)
        return db.allergens.find_one({'_id': allergen_id})
    except Exception as e:
        logger.error(f"Error getting allergen by ID: {str(e)}")
        raise AllergenError(f"Failed to get allergen: {str(e)}")

def create_allergen(db, allergen_data: Dict) -> Dict:
    """
    Create new allergen entry
    
    Args:
        db: MongoDB database instance
        allergen_data: Allergen data to insert
        
    Returns:
        Created allergen document
    """
    try:
        #--------------------------------------------------#
        #              Validate required fields            #
        #--------------------------------------------------#
        required_fields = ['ingredient', 'severity', 'reaction_type']
        missing_fields = [f for f in required_fields if f not in allergen_data]
        if missing_fields:
            raise AllergenError(f"Missing required fields: {', '.join(missing_fields)}")

        #--------------------------------------------------#
        #                  Add timestamps                  #
        #--------------------------------------------------#
        allergen_data.update({
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        })

        result = db.allergens.insert_one(allergen_data)
        return db.allergens.find_one({'_id': result.inserted_id})
    except Exception as e:
        logger.error(f"Error creating allergen: {str(e)}")
        raise AllergenError(f"Failed to create allergen: {str(e)}")

def update_allergen(db, allergen_id: Union[str, ObjectId], update_data: Dict) -> Optional[Dict]:
    """
    Update existing allergen entry
    
    Args:
        db: MongoDB database instance
        allergen_id: ID of allergen to update
        update_data: Data to update
        
    Returns:
        Updated allergen document or None if not found
    """
    try:
        if isinstance(allergen_id, str):
            allergen_id = ObjectId(allergen_id)

        update_data['updated_at'] = datetime.utcnow()
        
        result = db.allergens.find_one_and_update(
            {'_id': allergen_id},
            {'$set': update_data},
            return_document=True
        )
        return result
    except Exception as e:
        logger.error(f"Error updating allergen: {str(e)}")
        raise AllergenError(f"Failed to update allergen: {str(e)}")

def delete_allergen(db, allergen_id: Union[str, ObjectId]) -> bool:
    """
    Delete allergen entry
    
    Args:
        db: MongoDB database instance
        allergen_id: ID of allergen to delete
        
    Returns:
        True if deleted, False if not found
    """
    try:
        if isinstance(allergen_id, str):
            allergen_id = ObjectId(allergen_id)

        result = db.allergens.delete_one({'_id': allergen_id})
        return result.deleted_count > 0
    except Exception as e:
        logger.error(f"Error deleting allergen: {str(e)}")
        raise AllergenError(f"Failed to delete allergen: {str(e)}")

def search_allergens(
    db,
    query: str = None,
    severity: str = None,
    reaction_type: str = None
) -> List[Dict]:
    """
    Search allergens with multiple criteria
    
    Args:
        db: MongoDB database instance
        query: Search query for ingredient name
        severity: Filter by severity level
        reaction_type: Filter by reaction type
        
    Returns:
        List of matching allergen documents
    """
    try:
        search_query = {}
        
        if query:
            search_query['ingredient'] = {'$regex': query, '$options': 'i'}
        if severity:
            search_query['severity'] = severity
        if reaction_type:
            search_query['reaction_type'] = reaction_type

        return list(db.allergens.find(search_query))
    except Exception as e:
        logger.error(f"Error searching allergens: {str(e)}")
        raise AllergenError(f"Failed to search allergens: {str(e)}")

def validate_allergen_data(allergen_data: Dict) -> tuple[bool, Optional[str]]:
    """
    Validate allergen data
    
    Args:
        allergen_data: Allergen data to validate
        
    Returns:
        tuple of (is_valid, error_message)
    """
    try:
        #--------------------------------------------------#
        #                  Required fields                 #
        #--------------------------------------------------#
        required_fields = ['ingredient', 'severity', 'reaction_type']
        missing_fields = [f for f in required_fields if f not in allergen_data]
        if missing_fields:
            return False, f"Missing required fields: {', '.join(missing_fields)}"

        #--------------------------------------------------#
        #              Validate severity levels            #
        #--------------------------------------------------#
        valid_severities = ['low', 'medium', 'high', 'severe']
        if allergen_data['severity'] not in valid_severities:
            return False, f"Invalid severity level. Must be one of: {', '.join(valid_severities)}"

        #--------------------------------------------------#
        #           Validate reaction types                #
        #--------------------------------------------------#
        valid_reactions = ['digestive', 'skin', 'respiratory', 'anaphylactic']
        if allergen_data['reaction_type'] not in valid_reactions:
            return False, f"Invalid reaction type. Must be one of: {', '.join(valid_reactions)}"

        return True, None
    except Exception as e:
        logger.error(f"Error validating allergen data: {str(e)}")
        return False, f"Validation error: {str(e)}"
