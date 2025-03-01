"""
ID Service for generating and managing unique identifiers across the application.
Provides consistent ID generation following the system's established ID patterns.
"""
import logging
import random
import string
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Union, Any

from bson import ObjectId
from flask import g

logger = logging.getLogger(__name__)

class IDService:
    """
    Service for generating and managing unique identifiers across the application.
    Provides consistent ID formats for different entity types and ensures uniqueness.
    """
    
    def __init__(self, db):
        """
        Initialize the ID Service with a database connection.
        
        Args:
            db: MongoDB database instance
        """
        self.db = db
        self._counters = {}  # In-memory counter cache
    
    def _get_next_sequence(self, entity_type: str) -> int:
        """
        Get the next sequence number for a given entity type.
        Uses a combination of database counters and in-memory caching for efficiency.
        
        Args:
            entity_type: Type of entity (e.g., 'company', 'venue', 'employee')
            
        Returns:
            int: Next sequence number
        """
        try:
            # First try to increment counter in database
            counter_doc = self.db.id_counters.find_one_and_update(
                {'_id': entity_type},
                {'$inc': {'sequence': 1}},
                upsert=True,
                return_document=True
            )
            
            if counter_doc:
                self._counters[entity_type] = counter_doc['sequence']
                return counter_doc['sequence']
                
            # Fallback to local counter if database update fails
            if entity_type in self._counters:
                self._counters[entity_type] += 1
            else:
                self._counters[entity_type] = 1
                
            return self._counters[entity_type]
        except Exception as e:
            logger.error(f"Error generating sequence for {entity_type}: {str(e)}")
            # Last resort, generate pseudo-random number
            return int(time.time() * 1000) % 10000
    
    def generate_company_id(self) -> str:
        """
        Generate a unique company ID with format 'CNY-XXXX'.
        
        Returns:
            str: Unique company ID
        """
        sequence = self._get_next_sequence('company')
        return f"CNY-{sequence:04d}"
    
    def generate_venue_id(self, company_id: str) -> str:
        """
        Generate a unique venue ID linked to a company.
        Format: 'VEN-XXXX-YY' where XXXX is company sequence and YY is venue sequence.
        
        Args:
            company_id: Parent company ID
            
        Returns:
            str: Unique venue ID
        """
        # Extract company sequence from company_id (e.g., '2976' from 'CNY-2976')
        company_seq = company_id.split('-')[1]
        
        # Get next venue sequence for this company
        venue_seq = self._get_next_sequence(f'venue_{company_id}')
        
        return f"VEN-{company_seq}-{venue_seq:02d}"
    
    def generate_work_area_id(self, company_id: str) -> str:
        """
        Generate a unique work area ID.
        Format: 'WAI-XXXX-YYYY' where XXXX is company sequence and YYYY is work area sequence.
        
        Args:
            company_id: Parent company ID
            
        Returns:
            str: Unique work area ID
        """
        company_seq = company_id.split('-')[1]
        work_area_seq = self._get_next_sequence(f'workarea_{company_id}')
        
        return f"WAI-{company_seq}-{work_area_seq:04d}"
    
    def generate_employee_linking_id(self, company_id: str, venue_id: str, work_area_id: str) -> str:
        """
        Generate a unique employee linking ID.
        Format: 'EMP-XXXX-YYYY-ZZZZZZ' where XXXX is company sequence, YYYY is work area sequence,
        and ZZZZZZ is employee sequence.
        
        Args:
            company_id: Company ID
            venue_id: Venue ID
            work_area_id: Work area ID
            
        Returns:
            str: Unique employee linking ID
        """
        company_seq = company_id.split('-')[1]
        
        # Extract work area sequence from work_area_id (e.g., '3088' from 'WAI-2976-3088')
        work_area_seq = work_area_id.split('-')[2]
        
        # Get next employee sequence for this company
        employee_seq = self._get_next_sequence(f'employee_{company_id}')
        
        return f"EMP-{company_seq}-{work_area_seq}-{employee_seq:06d}"
    
    def generate_payroll_id(self, department_code: str, employee_seq: int) -> str:
        """
        Generate a unique payroll ID.
        Format: 'XX-YYYYYY' where XX is department code and YYYYYY is employee sequence.
        
        Args:
            department_code: Department code (e.g., 'DK' for kitchen, 'DB' for bar)
            employee_seq: Employee sequence number
            
        Returns:
            str: Unique payroll ID
        """
        # Extract employee sequence from linking_id if provided as string
        if isinstance(employee_seq, str) and '-' in employee_seq:
            parts = employee_seq.split('-')
            if len(parts) >= 4:
                employee_seq = int(parts[3])
        
        return f"{department_code}-{employee_seq:06d}"
    
    def generate_request_id(self) -> str:
        """
        Generate a unique request ID for tracking API requests and transactions.
        
        Returns:
            str: Unique request ID
        """
        return f"REQ-{uuid.uuid4().hex[:12].upper()}"
    
    def generate_transaction_id(self, transaction_type: str = "TRX") -> str:
        """
        Generate a unique transaction ID.
        
        Args:
            transaction_type: Type of transaction (e.g., 'PAY', 'REF', 'INV')
            
        Returns:
            str: Unique transaction ID
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        random_chars = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        
        return f"{transaction_type}-{timestamp}-{random_chars}"
    
    def is_valid_company_id(self, company_id: str) -> bool:
        """
        Validate a company ID format.
        
        Args:
            company_id: Company ID to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not company_id or not isinstance(company_id, str):
            return False
            
        parts = company_id.split('-')
        if len(parts) != 2 or parts[0] != 'CNY':
            return False
            
        # Check if second part is a number
        try:
            int(parts[1])
            return True
        except (ValueError, TypeError):
            return False
    
    def is_valid_venue_id(self, venue_id: str) -> bool:
        """
        Validate a venue ID format.
        
        Args:
            venue_id: Venue ID to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not venue_id or not isinstance(venue_id, str):
            return False
            
        parts = venue_id.split('-')
        if len(parts) != 3 or parts[0] != 'VEN':
            return False
            
        # Check if second and third parts are numbers
        try:
            int(parts[1])
            int(parts[2])
            return True
        except (ValueError, TypeError):
            return False
    
    def is_valid_work_area_id(self, work_area_id: str) -> bool:
        """
        Validate a work area ID format.
        
        Args:
            work_area_id: Work area ID to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not work_area_id or not isinstance(work_area_id, str):
            return False
            
        parts = work_area_id.split('-')
        if len(parts) != 3 or parts[0] != 'WAI':
            return False
            
        # Check if second and third parts are numbers
        try:
            int(parts[1])
            int(parts[2])
            return True
        except (ValueError, TypeError):
            return False
    
    def extract_company_id_from_venue(self, venue_id: str) -> Optional[str]:
        """
        Extract company ID from a venue ID.
        
        Args:
            venue_id: Venue ID (e.g., 'VEN-2976-30')
            
        Returns:
            str: Company ID (e.g., 'CNY-2976') or None if invalid
        """
        if not self.is_valid_venue_id(venue_id):
            return None
            
        parts = venue_id.split('-')
        return f"CNY-{parts[1]}"
    
    def create_business_structure(self, admin_user_id: str, business_data: Dict) -> Dict:
        """
        Create complete business structure with all necessary IDs and relationships.
        
        Args:
            admin_user_id: Admin user ID creating the business
            business_data: Business data including name and venues
            
        Returns:
            Dict: Created business structure with IDs
        """
        try:
            # Generate company ID
            company_id = self.generate_company_id()
            
            # Create business document
            business_doc = {
                'company_id': company_id,
                'company_name': business_data.get('company_name', ''),
                'director_name': business_data.get('director_name', ''),
                'ACN': business_data.get('ACN', ''),
                'admin_user_id': admin_user_id,
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow(),
                'head_office': business_data.get('head_office', {}),
                'venues': []
            }
            
            # Process venues
            venues = business_data.get('venues', [])
            for venue_data in venues:
                venue_id = self.generate_venue_id(company_id)
                venue = {
                    'venue_id': venue_id,
                    'venue_name': venue_data.get('venue_name', ''),
                    'venue_manager_id': venue_data.get('venue_manager_id', ''),
                    'venue_manager_name': venue_data.get('venue_manager_name', ''),
                    'workareas': []
                }
                
                # Process work areas
                workareas = venue_data.get('workareas', [])
                for workarea_data in workareas:
                    work_area_id = self.generate_work_area_id(company_id)
                    workarea = {
                        'work_area_id': work_area_id,
                        'work_area_name': workarea_data.get('work_area_name', '')
                    }
                    venue['workareas'].append(workarea)
                
                business_doc['venues'].append(venue)
            
            # Insert into database
            result = self.db.business_entities.insert_one(business_doc)
            business_doc['_id'] = result.inserted_id
            
            return business_doc
        except Exception as e:
            logger.error(f"Error creating business structure: {str(e)}")
            raise
    
    def update_venue_details(self, venue_id: str, details: Dict) -> bool:
        """
        Update venue details including location data.
        
        Args:
            venue_id: Venue ID to update
            details: Venue details to update
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_valid_venue_id(venue_id):
            return False
            
        try:
            # First update venue in business_entities collection
            result1 = self.db.business_entities.update_one(
                {'venues.venue_id': venue_id},
                {'$set': {
                    'venues.$.venue_name': details.get('venue_name', ''),
                    'venues.$.venue_manager_id': details.get('venue_manager_id', ''),
                    'venues.$.venue_manager_name': details.get('venue_manager_name', ''),
                    'updated_at': datetime.utcnow()
                }}
            )
            
            # Then update venue in business_venues collection
            result2 = self.db.business_venues.update_one(
                {'venue_id': venue_id},
                {'$set': {
                    'venue_name': details.get('venue_name', ''),
                    'venue_manager_name': details.get('venue_manager_name', ''),
                    'address': details.get('address', ''),
                    'suburb': details.get('suburb', ''),
                    'state': details.get('state', ''),
                    'post_code': details.get('post_code', ''),
                    'phone': details.get('phone', ''),
                    'email': details.get('email', '')
                }}
            )
            
            return result1.modified_count > 0 or result2.modified_count > 0
        except Exception as e:
            logger.error(f"Error updating venue details for {venue_id}: {str(e)}")
            return False
    
    def add_work_areas(self, venue_id: str, company_id: str, work_areas: List[Dict]) -> List[str]:
        """
        Add work areas to a venue and return their IDs.
        
        Args:
            venue_id: Venue ID to add work areas to
            company_id: Company ID
            work_areas: List of work area details
            
        Returns:
            List[str]: List of created work area IDs
        """
        if not self.is_valid_venue_id(venue_id) or not self.is_valid_company_id(company_id):
            return []
            
        try:
            work_area_docs = []
            work_area_ids = []
            
            for area in work_areas:
                work_area_id = self.generate_work_area_id(company_id)
                work_area = {
                    'work_area_id': work_area_id,
                    'work_area_name': area.get('work_area_name', ''),
                    'employees': area.get('employees', [])
                }
                work_area_docs.append(work_area)
                work_area_ids.append(work_area_id)
            
            # First update business_entities collection
            result1 = self.db.business_entities.update_one(
                {'venues.venue_id': venue_id},
                {'$push': {'venues.$.workareas': {'$each': work_area_docs}}}
            )
            
            # Then update business_venues collection
            result2 = self.db.business_venues.update_one(
                {'venue_id': venue_id},
                {'$push': {'workareas': {'$each': work_area_docs}}}
            )
            
            return work_area_ids if (result1.modified_count > 0 or result2.modified_count > 0) else []
        except Exception as e:
            logger.error(f"Error adding work areas to venue {venue_id}: {str(e)}")
            return []
    
    def create_employee(self, employee_data: Dict) -> Dict:
        """
        Create a new employee record with all necessary IDs.
        
        Args:
            employee_data: Employee data
            
        Returns:
            Dict: Created employee record with IDs
        """
        try:
            company_id = employee_data.get('company_id')
            venue_id = employee_data.get('venue_id')
            work_area_id = employee_data.get('work_area_id')
            
            if not company_id or not venue_id or not work_area_id:
                raise ValueError("Missing required IDs")
            
            # Generate linking ID
            linking_id = self.generate_employee_linking_id(company_id, venue_id, work_area_id)
            
            # Generate payroll ID
            department_code = self._get_department_code(work_area_id, employee_data.get('role_id'))
            employee_seq = int(linking_id.split('-')[3])
            payroll_id = self.generate_payroll_id(department_code, employee_seq)
            
            # Create employee document
            employee_doc = {
                'linking_id': linking_id,
                'payroll_id': payroll_id,
                'company_id': company_id,
                'company_name': employee_data.get('company_name', ''),
                'venue_id': venue_id,
                'venue_name': employee_data.get('venue_name', ''),
                'work_area_id': work_area_id,
                'work_area_name': employee_data.get('work_area_name', ''),
                'role_id': employee_data.get('role_id', ''),
                'role_name': employee_data.get('role_name', ''),
                'first_name': employee_data.get('first_name', ''),
                'last_name': employee_data.get('last_name', ''),
                'preferred_name': employee_data.get('preferred_name', ''),
                'date_of_birth': employee_data.get('date_of_birth'),
                'address': employee_data.get('address', ''),
                'suburb': employee_data.get('suburb', ''),
                'state': employee_data.get('state', ''),
                'post_code': employee_data.get('post_code', ''),
                'personal_contact': employee_data.get('personal_contact', ''),
                'next_of_kin': employee_data.get('next_of_kin', {}),
                'work_email': employee_data.get('work_email', ''),
                'password': employee_data.get('password', ''),
                'permissions': employee_data.get('permissions', []),
                'employment_details': employee_data.get('employment_details', {}),
                'leave_entitlements': employee_data.get('leave_entitlements', {}),
                'created_at': datetime.utcnow()
            }
            
            # Insert into database
            result = self.db.business_users.insert_one(employee_doc)
            employee_doc['_id'] = result.inserted_id
            
            # Also add employee to venue work area
            self.db.business_venues.update_one(
                {'venue_id': venue_id, 'workareas.work_area_id': work_area_id},
                {'$push': {'workareas.$.employees': {
                    'linking_id': linking_id,
                    'payroll_id': payroll_id,
                    'role_id': employee_data.get('role_id', ''),
                    'role_name': employee_data.get('role_name', ''),
                    'preferred_name': employee_data.get('preferred_name', '')
                }}}
            )
            
            return employee_doc
        except Exception as e:
            logger.error(f"Error creating employee: {str(e)}")
            raise
    
    def _get_department_code(self, work_area_id: str, role_id: str) -> str:
        """
        Determine department code for payroll ID based on work area and role.
        
        Args:
            work_area_id: Work area ID
            role_id: Role ID
            
        Returns:
            str: Department code (e.g., 'DK', 'DB')
        """
        # Default mappings
        area_to_dept = {
            'kitchen': 'DK',
            'bar': 'DB',
            'restaurant': 'DR',
            'venue': 'DV',
            'reception': 'DR',
            'guest services': 'DG',
            'service': 'DS'
        }
        
        # Extract work area name from database if available
        try:
            venue_doc = self.db.business_venues.find_one(
                {'workareas.work_area_id': work_area_id},
                {'workareas.$': 1}
            )
            
            if venue_doc and 'workareas' in venue_doc and len(venue_doc['workareas']) > 0:
                work_area_name = venue_doc['workareas'][0].get('work_area_name', '').lower()
                if work_area_name in area_to_dept:
                    return area_to_dept[work_area_name]
        except Exception as e:
            logger.warning(f"Error getting work area name: {str(e)}")
        
        # Fallback to role prefix if work area lookup fails
        if role_id and isinstance(role_id, str) and len(role_id) >= 3:
            role_prefix = role_id[:3].upper()
            if role_prefix == 'BOH':
                return 'DK'  # Back of House (Kitchen)
            elif role_prefix == 'FOH':
                return 'DS'  # Front of House (Service)
            elif role_prefix == 'ADM':
                return 'DA'  # Admin
            elif role_prefix == 'GSH':
                return 'DG'  # Guest Services
        
        # Final fallback
        return 'DE'  # Default Employee
