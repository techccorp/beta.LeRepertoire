# -----------------------------------------------#
#         utils/logging/audit_logger.py          #
# -----------------------------------------------#

import logging
from datetime import datetime
from typing import Optional, Dict, Any
from flask import current_app, request, g
import json

logger = logging.getLogger(__name__)

class AuditLogger:
    """
    Handles audit logging for security and compliance tracking.
    Provides comprehensive logging for authentication and user actions.
    """

    @classmethod
    def log_event(
        cls,
        event_type: str,
        user_id: str,
        business_id: Optional[str],
        message: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log an audit event with detailed information.
        
        Args:
            event_type: Type of event (login, logout, etc.)
            user_id: User identifier (payroll_id)
            business_id: Associated business identifier
            message: Event description
            metadata: Additional event data
        """
        try:
            event_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'user_id': user_id,
                'business_id': business_id,
                'message': message,
                'request_id': getattr(g, 'request_id', None),
                'ip_address': request.remote_addr if request else None,
                'user_agent': request.user_agent.string if request and request.user_agent else None,
                'metadata': metadata or {}
            }

            # Add request context if available
            if request:
                event_data.update({
                    'method': request.method,
                    'endpoint': request.endpoint,
                    'url': request.url,
                })

            # Store in MongoDB
            try:
                current_app.mongo.db.audit_logs.insert_one(event_data)
            except Exception as e:
                logger.error(f"Failed to store audit log in MongoDB: {str(e)}")

            # Log to application logger
            log_message = (
                f"AUDIT: {event_type} | "
                f"User: {user_id} | "
                f"Business: {business_id or 'N/A'} | "
                f"{message}"
            )
            logger.info(log_message)

        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}")

    @classmethod
    def log_auth_event(
        cls,
        event_type: str,
        user_id: str,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log authentication-specific events.
        
        Args:
            event_type: Type of auth event (login, logout, token_refresh)
            user_id: User identifier (payroll_id)
            success: Whether the auth event was successful
            metadata: Additional auth event data
        """
        try:
            auth_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': f"AUTH_{event_type}",
                'user_id': user_id,
                'success': success,
                'request_id': getattr(g, 'request_id', None),
                'ip_address': request.remote_addr if request else None,
                'user_agent': request.user_agent.string if request and request.user_agent else None,
                'metadata': metadata or {}
            }

            # Store in MongoDB
            try:
                current_app.mongo.db.auth_logs.insert_one(auth_data)
            except Exception as e:
                logger.error(f"Failed to store auth log in MongoDB: {str(e)}")

            # Log to application logger
            status = "SUCCESS" if success else "FAILED"
            log_message = (
                f"AUTH: {event_type} | "
                f"Status: {status} | "
                f"User: {user_id}"
            )
            logger.info(log_message)

        except Exception as e:
            logger.error(f"Failed to create auth log: {str(e)}")

    @classmethod
    def get_user_activity(
        cls,
        user_id: str,
        start_date: datetime,
        end_date: datetime
    ) -> list:
        """
        Retrieve user activity logs.
        
        Args:
            user_id: User identifier to fetch logs for
            start_date: Start of date range
            end_date: End of date range
            
        Returns:
            List of activity log entries
        """
        try:
            query = {
                'user_id': user_id,
                'timestamp': {
                    '$gte': start_date.isoformat(),
                    '$lte': end_date.isoformat()
                }
            }

            # Combine logs from both collections
            audit_logs = list(current_app.mongo.db.audit_logs.find(query))
            auth_logs = list(current_app.mongo.db.auth_logs.find(query))
            
            # Merge and sort by timestamp
            all_logs = audit_logs + auth_logs
            return sorted(all_logs, key=lambda x: x['timestamp'], reverse=True)

        except Exception as e:
            logger.error(f"Failed to retrieve user activity: {str(e)}")
            return []

    @classmethod
    def cleanup_old_logs(cls, days_to_keep: int = 90) -> None:
        """
        Clean up old log entries.
        
        Args:
            days_to_keep: Number of days of logs to retain
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
            
            # Clean up audit logs
            current_app.mongo.db.audit_logs.delete_many({
                'timestamp': {'$lt': cutoff_date.isoformat()}
            })
            
            # Clean up auth logs
            current_app.mongo.db.auth_logs.delete_many({
                'timestamp': {'$lt': cutoff_date.isoformat()}
            })
            
            logger.info(f"Cleaned up logs older than {days_to_keep} days")
            
        except Exception as e:
            logger.error(f"Failed to cleanup old logs: {str(e)}")
