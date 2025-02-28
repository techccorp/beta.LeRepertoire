# ------------------------------------------------------------
#modules/notifications/notifications_manager.py
# ------------------------------------------------------------
from typing import Dict, List, Optional, Union
from datetime import datetime
from bson import ObjectId
import logging

logger = logging.getLogger(__name__)

class NotificationManager:
    """Manages notifications and alerts for business entities"""

    def __init__(self, db):
        self.db = db
        self.notification_types = {
            'system': {
                'password_reset': {
                    'priority': 'high',
                    'expiry_hours': 24,
                    'requires_action': True
                },
                'account_locked': {
                    'priority': 'high',
                    'expiry_hours': 24,
                    'requires_action': True
                },
                'security_alert': {
                    'priority': 'critical',
                    'expiry_hours': 48,
                    'requires_action': True
                }
            },
            'business': {
                'role_change': {
                    'priority': 'medium',
                    'expiry_hours': 72,
                    'requires_action': False
                },
                'venue_update': {
                    'priority': 'medium',
                    'expiry_hours': 72,
                    'requires_action': False
                },
                'staff_added': {
                    'priority': 'medium',
                    'expiry_hours': 72,
                    'requires_action': True
                }
            },
            'venue': {
                'schedule_change': {
                    'priority': 'medium',
                    'expiry_hours': 48,
                    'requires_action': False
                },
                'staff_update': {
                    'priority': 'medium',
                    'expiry_hours': 48,
                    'requires_action': False
                },
                'resource_alert': {
                    'priority': 'high',
                    'expiry_hours': 24,
                    'requires_action': True
                }
            }
        }

    def create_notification(
        self,
        notification_type: str,
        context_type: str,
        user_id: str,
        message: str,
        context_data: Dict,
        target_users: Optional[List[str]] = None,
        metadata: Optional[Dict] = None
    ) -> Union[str, None]:
        """
        Create a new notification
        """
        try:
            if context_type not in self.notification_types:
                raise ValueError(f"Invalid context type: {context_type}")

            type_config = self.notification_types[context_type].get(notification_type)
            if not type_config:
                raise ValueError(f"Invalid notification type: {notification_type}")

            # Calculate expiry time
            expiry_time = datetime.utcnow().replace(
                hour=23, minute=59, second=59
            ) + timedelta(hours=type_config['expiry_hours'])

            # Prepare notification document
            notification = {
                'notification_id': str(ObjectId()),
                'type': notification_type,
                'context_type': context_type,
                'message': message,
                'created_by': user_id,
                'created_at': datetime.utcnow(),
                'expires_at': expiry_time,
                'priority': type_config['priority'],
                'requires_action': type_config['requires_action'],
                'status': 'pending',
                'context_data': context_data,
                'metadata': metadata or {},
                'target_users': target_users or [],
                'read_by': [],
                'actioned_by': []
            }

            # Insert notification
            result = self.db[Config.COLLECTION_NOTIFICATIONS].insert_one(notification)
            if result.inserted_id:
                logger.info(f"Created notification: {notification['notification_id']}")
                
                # Process immediate notifications if needed
                if type_config['priority'] in ['critical', 'high']:
                    self._process_immediate_notification(notification)
                
                return notification['notification_id']

            return None

        except Exception as e:
            logger.error(f"Error creating notification: {str(e)}")
            return None

    def get_user_notifications(
        self,
        user_id: str,
        context_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict]:
        """
        Get notifications for a user
        """
        try:
            query = {
                '$or': [
                    {'target_users': user_id},
                    {'target_users': {'$exists': False}}
                ],
                'expires_at': {'$gt': datetime.utcnow()}
            }

            if context_type:
                query['context_type'] = context_type
            if status:
                query['status'] = status

            notifications = self.db[Config.COLLECTION_NOTIFICATIONS].find(
                query
            ).sort(
                [('created_at', -1)]
            ).limit(limit)

            return list(notifications)

        except Exception as e:
            logger.error(f"Error retrieving notifications: {str(e)}")
            return []

    def mark_as_read(self, notification_id: str, user_id: str) -> bool:
        """
        Mark notification as read for user
        """
        try:
            result = self.db[Config.COLLECTION_NOTIFICATIONS].update_one(
                {'notification_id': notification_id},
                {
                    '$addToSet': {'read_by': user_id},
                    '$set': {'updated_at': datetime.utcnow()}
                }
            )
            return bool(result.modified_count)

        except Exception as e:
            logger.error(f"Error marking notification as read: {str(e)}")
            return False

    def action_notification(
        self,
        notification_id: str,
        user_id: str,
        action: str,
        action_data: Optional[Dict] = None
    ) -> bool:
        """
        Take action on a notification
        """
        try:
            notification = self.db[Config.COLLECTION_NOTIFICATIONS].find_one({
                'notification_id': notification_id
            })

            if not notification:
                return False

            if not notification.get('requires_action'):
                return False

            update_data = {
                'status': 'actioned',
                'actioned_by': user_id,
                'action_taken': action,
                'action_data': action_data or {},
                'actioned_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }

            result = self.db[Config.COLLECTION_NOTIFICATIONS].update_one(
                {'notification_id': notification_id},
                {'$set': update_data}
            )

            if result.modified_count:
                self._process_notification_action(notification, action, action_data)
                return True

            return False

        except Exception as e:
            logger.error(f"Error actioning notification: {str(e)}")
            return False

    def delete_notification(self, notification_id: str, user_id: str) -> bool:
        """
        Delete a notification
        """
        try:
            result = self.db[Config.COLLECTION_NOTIFICATIONS].delete_one({
                'notification_id': notification_id,
                'created_by': user_id
            })
            return bool(result.deleted_count)

        except Exception as e:
            logger.error(f"Error deleting notification: {str(e)}")
            return False

    def clear_expired_notifications(self) -> int:
        """
        Clear expired notifications
        """
        try:
            result = self.db[Config.COLLECTION_NOTIFICATIONS].delete_many({
                'expires_at': {'$lt': datetime.utcnow()}
            })
            return result.deleted_count

        except Exception as e:
            logger.error(f"Error clearing expired notifications: {str(e)}")
            return 0

    def _process_immediate_notification(self, notification: Dict):
        """
        Process high-priority notifications requiring immediate attention
        """
        try:
            if notification['priority'] == 'critical':
                # Implement critical notification handling
                self._send_critical_alert(notification)
            
            elif notification['priority'] == 'high':
                # Implement high-priority notification handling
                self._send_high_priority_alert(notification)

        except Exception as e:
            logger.error(f"Error processing immediate notification: {str(e)}")

    def _process_notification_action(
        self,
        notification: Dict,
        action: str,
        action_data: Dict
    ):
        """
        Process actions taken on notifications
        """
        try:
            # Handle different action types
            if notification['type'] == 'password_reset':
                self._handle_password_reset_action(notification, action_data)
            elif notification['type'] == 'account_locked':
                self._handle_account_locked_action(notification, action_data)
            elif notification['type'] == 'staff_added':
                self._handle_staff_added_action(notification, action_data)

        except Exception as e:
            logger.error(f"Error processing notification action: {str(e)}")

    def _send_critical_alert(self, notification: Dict):
        """
        Handle critical alert notifications
        """
        # Implement critical alert mechanism
        # This could include immediate admin notifications,
        # SMS alerts, or other urgent communication methods
        pass

    def _send_high_priority_alert(self, notification: Dict):
        """
        Handle high-priority alert notifications
        """
        # Implement high-priority alert mechanism
        # This could include admin dashboard alerts,
        # email notifications, or other priority communications
        pass

    def _handle_password_reset_action(self, notification: Dict, action_data: Dict):
        """
        Handle password reset notification actions
        """
        # Implement password reset action handling
        pass

    def _handle_account_locked_action(self, notification: Dict, action_data: Dict):
        """
        Handle account locked notification actions
        """
        # Implement account locked action handling
        pass

    def _handle_staff_added_action(self, notification: Dict, action_data: Dict):
        """
        Handle staff added notification actions
        """
        # Implement staff added action handling
        pass
