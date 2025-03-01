from datetime import datetime, timedelta
from pymongo import ReturnDocument, ASCENDING, IndexModel
from bson import ObjectId
import bcrypt
import logging
import re
from typing import Dict, List, Optional, Union

logger = logging.getLogger(__name__)

class UserModelError(Exception):
    """Custom exception for UserModel errors"""
    pass

class UserModel:
    def __init__(self, db, config):
        """Initialize UserModel with database connection and configuration"""
        self.db = db
        self.config = config
        self.collection = db[config.COLLECTION_BUSINESS_USERS]
        self.setup_indexes()

    def setup_indexes(self):
        """Create necessary indexes for the collection"""
        try:
            indexes = [
                IndexModel([("pay_details.payroll_id", ASCENDING)], unique=True),
                IndexModel([("pay_details.email_work", ASCENDING)], unique=True),
                IndexModel([("email_personal", ASCENDING)]),
                IndexModel([
                    ("linked.business_id", ASCENDING),
                    ("linked.venue_id", ASCENDING)
                ]),
                IndexModel([("work_area_id", ASCENDING)]),
                IndexModel([("role", ASCENDING)]),
                IndexModel([("status", ASCENDING)]),
                IndexModel([("created_at", ASCENDING)]),
                IndexModel([("hired_on", ASCENDING)])
            ]
            self.collection.create_indexes(indexes)
            logger.info("User collection indexes created successfully")
        except Exception as e:
            logger.error(f"Error creating indexes: {str(e)}")
            raise UserModelError(f"Failed to create indexes: {str(e)}")

    def validate_user_data(self, user_data: Dict) -> None:
        """Validate user data against schema requirements"""
        try:
            # Check required fields
            for field in self.config.USER_SCHEMA['required_fields']:
                if not self._get_nested_value(user_data, field):
                    raise ValueError(f"Missing required field: {field}")

            # Validate payroll ID format
            payroll_id = user_data.get('pay_details', {}).get('payroll_id')
            if not re.match(self.config.USER_SCHEMA['payroll_id_pattern'], payroll_id):
                raise ValueError("Invalid payroll ID format")

            # Validate email formats
            if not self._validate_email(user_data.get('pay_details', {}).get('email_work')):
                raise ValueError("Invalid work email format")
            if not self._validate_email(user_data.get('email_personal')):
                raise ValueError("Invalid personal email format")

            # Validate date formats
            if not self._validate_date(user_data.get('D.O.B')):
                raise ValueError("Invalid date of birth format")
            if not self._validate_date(user_data.get('hired_on')):
                raise ValueError("Invalid hire date format")

        except ValueError as e:
            raise UserModelError(str(e))
        except Exception as e:
            logger.error(f"Validation error: {str(e)}")
            raise UserModelError(f"Validation failed: {str(e)}")

    def create_user(self, user_data: Dict) -> str:
        """Create a new user with proper schema validation"""
        try:
            # Validate user data
            self.validate_user_data(user_data)

            # Hash password
            user_data['pay_details']['password'] = self._hash_password(
                user_data['pay_details']['password']
            )

            # Set default values and timestamps
            now = datetime.utcnow()
            user_data.update({
                'status': 'active',
                'created_at': now,
                'updated_at': now,
                'last_login': None,
                'pay_details': {
                    **user_data['pay_details'],
                    'leave_entitlements': self._initialize_leave_entitlements(),
                    'accrued_employment': self._initialize_employment_stats()
                }
            })

            # Insert user
            result = self.collection.insert_one(user_data)
            logger.info(f"Created user with payroll ID: {user_data['pay_details']['payroll_id']}")
            return str(result.inserted_id)

        except UserModelError as e:
            raise
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            raise UserModelError(f"Failed to create user: {str(e)}")

    def update_user(self, payroll_id: str, update_data: Dict) -> Dict:
        """Update user data with validation"""
        try:
            # Remove protected fields
            protected_fields = ['_id', 'pay_details.payroll_id', 'created_at', 'status']
            update_data = self._remove_protected_fields(update_data, protected_fields)

            # Validate update data
            if any(field in update_data for field in self.config.USER_SCHEMA['required_fields']):
                self.validate_user_data({**self.find_by_payroll_id(payroll_id), **update_data})

            update_data['updated_at'] = datetime.utcnow()

            result = self.collection.find_one_and_update(
                {"pay_details.payroll_id": payroll_id, "status": "active"},
                {"$set": update_data},
                return_document=ReturnDocument.AFTER
            )

            if not result:
                raise UserModelError("User not found or inactive")

            logger.info(f"Updated user with payroll ID: {payroll_id}")
            return result

        except UserModelError as e:
            raise
        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            raise UserModelError(f"Failed to update user: {str(e)}")

    def update_password(self, payroll_id: str, current_password: str, new_password: str) -> bool:
        """Update user's password with verification"""
        try:
            user = self.find_by_payroll_id(payroll_id)
            if not user:
                raise UserModelError("User not found")

            # Verify current password
            if not self.verify_password(user['pay_details']['password'], current_password):
                raise UserModelError("Current password is incorrect")

            # Validate new password
            if not self._validate_password(new_password):
                raise UserModelError("New password does not meet requirements")

            # Update password
            hashed_password = self._hash_password(new_password)
            result = self.collection.update_one(
                {"pay_details.payroll_id": payroll_id, "status": "active"},
                {
                    "$set": {
                        "pay_details.password": hashed_password,
                        "updated_at": datetime.utcnow()
                    }
                }
            )

            success = result.modified_count > 0
            if success:
                logger.info(f"Password updated for user: {payroll_id}")
            return success

        except UserModelError as e:
            raise
        except Exception as e:
            logger.error(f"Error updating password: {str(e)}")
            raise UserModelError(f"Failed to update password: {str(e)}")

    def find_by_payroll_id(self, payroll_id: str) -> Optional[Dict]:
        """Find a user by payroll ID"""
        try:
            return self.collection.find_one({
                "pay_details.payroll_id": payroll_id,
                "status": "active"
            })
        except Exception as e:
            logger.error(f"Error finding user: {str(e)}")
            raise UserModelError(f"Failed to find user: {str(e)}")

    def update_last_login(self, payroll_id: str) -> bool:
        """Update user's last login timestamp"""
        try:
            result = self.collection.update_one(
                {"pay_details.payroll_id": payroll_id, "status": "active"},
                {"$set": {"last_login": datetime.utcnow()}}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error updating last login: {str(e)}")
            raise UserModelError(f"Failed to update last login: {str(e)}")

    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt(rounds=self.config.BCRYPT_LOG_ROUNDS)
        ).decode('utf-8')

    def verify_password(self, stored_password: str, provided_password: str) -> bool:
        """Verify password using bcrypt"""
        return bcrypt.checkpw(
            provided_password.encode('utf-8'),
            stored_password.encode('utf-8')
        )

    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        if not email:
            return False
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def _validate_date(self, date_str: str) -> bool:
        """Validate date format (YYYY-MM-DD)"""
        if not date_str:
            return False
        pattern = r'^\d{4}-\d{2}-\d{2}$'
        return bool(re.match(pattern, date_str))

    def _validate_password(self, password: str) -> bool:
        """Validate password against requirements"""
        requirements = self.config.USER_SCHEMA['password_requirements']
        
        if len(password) < requirements['min_length']:
            return False
        if requirements['require_uppercase'] and not re.search(r'[A-Z]', password):
            return False
        if requirements['require_lowercase'] and not re.search(r'[a-z]', password):
            return False
        if requirements['require_numbers'] and not re.search(r'\d', password):
            return False
        if requirements['require_special'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
            
        return True

    def _initialize_leave_entitlements(self) -> Dict:
        """Initialize leave entitlements structure"""
        return {
            'holiday_accrued': 0,
            'holiday_taken': 0,
            'sick_accrued': 0,
            'sick_taken': 0,
            'carers_accrued': 0,
            'carers_taken': 0,
            'bereavement_accrued': 0,
            'bereavement_taken': 0,
            'maternity_entitlement': 0,
            'maternity_taken': 0,
            'unpaid_leave_taken': 0
        }

    def _initialize_employment_stats(self) -> Dict:
        """Initialize employment statistics structure"""
        return {
            'days_employed': 0,
            'unpaid_leave': 0,
            'salary': 0,
            'tax_withheld': 0,
            'salary_ytd': 0,
            'tax_withheld_ytd': 0
        }

    def _get_nested_value(self, dict_obj: Dict, path: str) -> any:
        """Get nested dictionary value using dot notation"""
        keys = path.split('.')
        value = dict_obj
        for key in keys:
            if not isinstance(value, dict):
                return None
            value = value.get(key)
            if value is None:
                return None
        return value

    def _remove_protected_fields(self, data: Dict, protected_fields: List[str]) -> Dict:
        """Remove protected fields from update data"""
        result = data.copy()
        for field in protected_fields:
            keys = field.split('.')
            current = result
            for key in keys[:-1]:
                if key in current:
                    current = current[key]
            if keys[-1] in current:
                del current[keys[-1]]
        return result