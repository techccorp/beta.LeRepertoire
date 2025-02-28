"""
Notification Utilities
Provides functions for managing notifications, including in-app notifications, 
email notifications, and SMS notifications.
"""

import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bson.objectid import ObjectId
from pymongo.errors import PyMongoError
from datetime import datetime
import requests
import json

# Import required utilities
from .database_utils import get_db
from .error_utils import ValidationError, NotFoundError, DatabaseError, AppError
from config import Config

logger = logging.getLogger(__name__)

def send_email_notification(recipient_email, subject, message, html_content=None, sender_name=None):
    """
    Send an email notification to a user.
    
    Args:
        recipient_email (str): Recipient's email address
        subject (str): Email subject
        message (str): Plain text message
        html_content (str, optional): HTML content version of the email. Defaults to None.
        sender_name (str, optional): Name to display as sender. Defaults to None.
        
    Returns:
        bool: True if email was sent successfully
        
    Raises:
        ValidationError: If email parameters are invalid
        AppError: If email sending fails
    """
    try:
        # Validate email parameters
        if not recipient_email or not subject or not message:
            raise ValidationError("Email recipient, subject, and message are required")
            
        if not isinstance(recipient_email, str) or '@' not in recipient_email:
            raise ValidationError(f"Invalid email address: {recipient_email}")
            
        # Get email configuration from Config
        smtp_server = Config.SMTP_SERVER
        smtp_port = Config.SMTP_PORT
        smtp_username = Config.SMTP_USERNAME
        smtp_password = Config.SMTP_PASSWORD
        sender_email = Config.SMTP_SENDER
        
        if not smtp_server or not smtp_port or not sender_email:
            raise ValidationError("SMTP configuration is incomplete")
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{sender_name} <{sender_email}>" if sender_name else sender_email
        msg['To'] = recipient_email
        
        # Add plain text version
        part1 = MIMEText(message, 'plain')
        msg.attach(part1)
        
        # Add HTML version if provided
        if html_content:
            part2 = MIMEText(html_content, 'html')
            msg.attach(part2)
        
        # Create secure SSL context
        context = ssl.create_default_context()
        
        # Connect to server and send email
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
            server.login(smtp_username, smtp_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
        
        logger.info(f"Email notification sent to {recipient_email}: {subject}")
        
        # Log the notification in the database
        notification_data = {
            'type': 'email',
            'recipient_email': recipient_email,
            'subject': subject,
            'message': message,
            'status': 'sent',
            'sent_at': datetime.utcnow()
        }
        
        db = get_db()
        db.notification_logs.insert_one(notification_data)
        
        return True
        
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error sending email to {recipient_email}: {str(e)}")
        raise AppError(f"Failed to send email: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error sending email to {recipient_email}: {str(e)}")
        raise AppError(f"Failed to send email: {str(e)}")

def send_sms_notification(phone_number, message):
    """
    Send an SMS notification to a user.
    
    Args:
        phone_number (str): Recipient's phone number
        message (str): SMS message content
        
    Returns:
        bool: True if SMS was sent successfully
        
    Raises:
        ValidationError: If SMS parameters are invalid
        AppError: If SMS sending fails
    """
    try:
        # Validate SMS parameters
        if not phone_number or not message:
            raise ValidationError("Phone number and message are required")
            
        # Basic phone number validation
        if not isinstance(phone_number, str) or not phone_number.startswith('+'):
            raise ValidationError(f"Invalid phone number format: {phone_number}. Must include country code starting with '+'")
            
        # Get SMS configuration from Config
        sms_api_key = Config.SMS_API_KEY
        sms_api_url = Config.SMS_API_URL
        sms_sender_id = Config.SMS_SENDER_ID
        
        if not sms_api_key or not sms_api_url:
            raise ValidationError("SMS API configuration is incomplete")
            
        # Prepare API request
        payload = {
            'api_key': sms_api_key,
            'to': phone_number,
            'message': message,
            'sender_id': sms_sender_id
        }
        
        # Send SMS via API
        response = requests.post(sms_api_url, json=payload)
        
        # Check response
        if response.status_code != 200:
            logger.error(f"SMS API error: {response.status_code} - {response.text}")
            raise AppError(f"SMS API error: {response.status_code}")
            
        # Parse response
        result = response.json()
        
        if not result.get('success', False):
            logger.error(f"SMS sending failed: {result.get('message', 'Unknown error')}")
            raise AppError(f"SMS sending failed: {result.get('message', 'Unknown error')}")
            
        logger.info(f"SMS notification sent to {phone_number}")
        
        # Log the notification in the database
        notification_data = {
            'type': 'sms',
            'recipient_phone': phone_number,
            'message': message,
            'status': 'sent',
            'sent_at': datetime.utcnow()
        }
        
        db = get_db()
        db.notification_logs.insert_one(notification_data)
        
        return True
        
    except requests.RequestException as e:
        logger.error(f"HTTP error sending SMS to {phone_number}: {str(e)}")
        raise AppError(f"Failed to send SMS: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error sending SMS to {phone_number}: {str(e)}")
        raise AppError(f"Failed to send SMS: {str(e)}")

def create_notification(user_id, notification_type, title, message, data=None, priority='normal'):
    """
    Create an in-app notification for a user.
    
    Args:
        user_id (str): ID of the user (linking_id, payroll_id, or ObjectId)
        notification_type (str): Type of notification (e.g., 'info', 'warning', 'alert', 'task')
        title (str): Notification title
        message (str): Notification message
        data (dict, optional): Additional data to store with the notification. Defaults to None.
        priority (str, optional): Notification priority ('low', 'normal', 'high', 'urgent'). Defaults to 'normal'.
        
    Returns:
        dict: Created notification document
        
    Raises:
        ValidationError: If notification parameters are invalid
        DatabaseError: If database operation fails
    """
    try:
        # Validate notification parameters
        if not user_id or not notification_type or not title or not message:
            raise ValidationError("User ID, notification type, title, and message are required")
            
        # Validate notification type
        valid_types = ['info', 'warning', 'alert', 'task', 'announcement', 'reminder']
        if notification_type not in valid_types:
            raise ValidationError(f"Invalid notification type: {notification_type}. Must be one of: {', '.join(valid_types)}")
            
        # Validate priority
        valid_priorities = ['low', 'normal', 'high', 'urgent']
        if priority not in valid_priorities:
            raise ValidationError(f"Invalid priority: {priority}. Must be one of: {', '.join(valid_priorities)}")
            
        # Create notification document
        notification = {
            'user_id': user_id,
            'type': notification_type,
            'title': title,
            'message': message,
            'data': data or {},
            'priority': priority,
            'is_read': False,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        # Insert notification into database
        db = get_db()
        result = db.notifications.insert_one(notification)
        
        # Return the created notification
        created_notification = db.notifications.find_one({'_id': result.inserted_id})
        
        logger.info(f"Created notification for user {user_id}: {title}")
        
        return created_notification
        
    except PyMongoError as e:
        logger.error(f"Database error creating notification: {str(e)}")
        raise DatabaseError(f"Failed to create notification: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error creating notification: {str(e)}")
        raise AppError(f"Failed to create notification: {str(e)}")

def get_notifications_for_user(user_id, include_read=False, limit=50, skip=0, sort_by='created_at', sort_order=-1):
    """
    Get notifications for a specific user.
    
    Args:
        user_id (str): ID of the user (linking_id, payroll_id, or ObjectId)
        include_read (bool, optional): Whether to include read notifications. Defaults to False.
        limit (int, optional): Maximum number of notifications to return. Defaults to 50.
        skip (int, optional): Number of notifications to skip. Defaults to 0.
        sort_by (str, optional): Field to sort by. Defaults to 'created_at'.
        sort_order (int, optional): Sort order (1 for ascending, -1 for descending). Defaults to -1.
        
    Returns:
        list: List of notification documents
        
    Raises:
        ValidationError: If parameters are invalid
        DatabaseError: If database operation fails
    """
    try:
        # Validate parameters
        if not user_id:
            raise ValidationError("User ID is required")
            
        # Prepare query
        query = {'user_id': user_id}
        
        # Filter out read notifications if requested
        if not include_read:
            query['is_read'] = False
            
        # Get notifications from database
        db = get_db()
        notifications = list(db.notifications.find(query)
                             .sort(sort_by, sort_order)
                             .skip(skip)
                             .limit(limit))
        
        logger.info(f"Retrieved {len(notifications)} notifications for user {user_id}")
        
        return notifications
        
    except PyMongoError as e:
        logger.error(f"Database error getting notifications: {str(e)}")
        raise DatabaseError(f"Failed to get notifications: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error getting notifications: {str(e)}")
        raise AppError(f"Failed to get notifications: {str(e)}")

def mark_notification_as_read(notification_id):
    """
    Mark a notification as read.
    
    Args:
        notification_id (str): ID of the notification to mark as read
        
    Returns:
        dict: Updated notification document
        
    Raises:
        NotFoundError: If notification not found
        DatabaseError: If database operation fails
    """
    try:
        db = get_db()
        
        # Convert string ID to ObjectId if needed
        if isinstance(notification_id, str) and ObjectId.is_valid(notification_id):
            notification_id = ObjectId(notification_id)
            
        # Check if notification exists
        notification = db.notifications.find_one({'_id': notification_id})
        
        if not notification:
            raise NotFoundError(f"Notification with ID {notification_id} not found")
            
        # Update notification
        result = db.notifications.update_one(
            {'_id': notification_id},
            {'$set': {
                'is_read': True,
                'read_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }}
        )
        
        if result.modified_count == 0:
            logger.warning(f"No changes made to notification {notification_id}")
            
        # Get updated notification
        updated_notification = db.notifications.find_one({'_id': notification_id})
        
        logger.info(f"Marked notification {notification_id} as read")
        
        return updated_notification
        
    except NotFoundError:
        raise
        
    except PyMongoError as e:
        logger.error(f"Database error marking notification as read: {str(e)}")
        raise DatabaseError(f"Failed to mark notification as read: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error marking notification as read: {str(e)}")
        raise AppError(f"Failed to mark notification as read: {str(e)}")

def delete_notification(notification_id):
    """
    Delete a notification.
    
    Args:
        notification_id (str): ID of the notification to delete
        
    Returns:
        bool: True if notification was deleted successfully
        
    Raises:
        NotFoundError: If notification not found
        DatabaseError: If database operation fails
    """
    try:
        db = get_db()
        
        # Convert string ID to ObjectId if needed
        if isinstance(notification_id, str) and ObjectId.is_valid(notification_id):
            notification_id = ObjectId(notification_id)
            
        # Check if notification exists
        notification = db.notifications.find_one({'_id': notification_id})
        
        if not notification:
            raise NotFoundError(f"Notification with ID {notification_id} not found")
            
        # Delete notification
        result = db.notifications.delete_one({'_id': notification_id})
        
        if result.deleted_count == 0:
            logger.warning(f"Notification {notification_id} could not be deleted")
            return False
            
        logger.info(f"Deleted notification {notification_id}")
        
        return True
        
    except NotFoundError:
        raise
        
    except PyMongoError as e:
        logger.error(f"Database error deleting notification: {str(e)}")
        raise DatabaseError(f"Failed to delete notification: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error deleting notification: {str(e)}")
        raise AppError(f"Failed to delete notification: {str(e)}")
