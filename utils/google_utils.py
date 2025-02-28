# ---------------------------------------#
#         utils/google_utils.py          #
# ---------------------------------------#
import requests
import logging
from google.oauth2 import credentials
from googleapiclient.errors import HttpError
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
import google.auth.transport.requests
from flask import current_app
from config.google_oauth_config import GoogleOAuthConfig, GoogleOAuthConfigError
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import io

logger = logging.getLogger(__name__)

class GoogleAPIError(Exception):
    """Custom exception for Google API errors"""
    pass

#----------------------------------------------#
#     API service definitions with versions    #
#----------------------------------------------#
API_SERVICES = {
    'calendar': {'name': 'calendar', 'version': 'v3'},
    'tasks': {'name': 'tasks', 'version': 'v1'},
    'gmail': {'name': 'gmail', 'version': 'v1'},
    'drive': {'name': 'drive', 'version': 'v3'},
    'sheets': {'name': 'sheets', 'version': 'v4'}
}

def validate_google_token(token: Dict) -> bool:
    """
    Validates a Google token to ensure it's still valid.
    
    Args:
        token: Google OAuth credentials dictionary
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        # Create credentials object from token
        creds = credentials.Credentials(**token)
        
        # Test token validity by making a lightweight API call
        service = build('tasks', 'v1', credentials=creds)
        service.tasklists().list().execute()
        return True
    except HttpError as e:
        logger.error(f"Token validation failed: {e}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred during token validation: {e}")
        return False

def get_google_service(service_key: str, credentials_dict: Dict) -> Any:
    """
    Initialize a Google API service.
    
    Args:
        service_key: Key identifying the service in API_SERVICES
        credentials_dict: Dictionary containing OAuth credentials
        
    Returns:
        Google API service instance
        
    Raises:
        GoogleAPIError: If service initialization fails
    """
    try:
        if service_key not in API_SERVICES:
            raise GoogleAPIError(f"Unknown service: {service_key}")

        creds = credentials.Credentials(**credentials_dict)
        service = build(
            API_SERVICES[service_key]['name'],
            API_SERVICES[service_key]['version'],
            credentials=creds,
            cache_discovery=False
        )
        return service
    except Exception as e:
        logger.error(f'Error initializing {service_key} service: {e}')
        raise GoogleAPIError(f"Failed to initialize {service_key} service")

#----------------------------------------------#
#                  Gmail                       #
#----------------------------------------------#
class GmailService:
    """Gmail service wrapper"""
    def __init__(self, credentials_dict: Dict):
        self.service = get_google_service('gmail', credentials_dict)

    def list_messages(self, query: str = None, max_results: int = 10) -> List[Dict]:
        """List Gmail messages"""
        try:
            messages = []
            request = self.service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            )
            while request is not None:
                response = request.execute()
                messages.extend(response.get('messages', []))
                request = self.service.users().messages().list_next(request, response)
            return messages
        except Exception as e:
            logger.error(f"Error listing Gmail messages: {e}")
            raise GoogleAPIError("Failed to list Gmail messages")

    def get_message(self, message_id: str) -> Dict:
        """Get a specific Gmail message"""
        try:
            return self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
        except Exception as e:
            logger.error(f"Error getting Gmail message: {e}")
            raise GoogleAPIError("Failed to get Gmail message")

    def send_message(self, to: str, subject: str, body: str, html: bool = False) -> Dict:
        """Send a Gmail message"""
        try:
            message = self._create_message('me', to, subject, body, html)
            return self.service.users().messages().send(
                userId='me',
                body=message
            ).execute()
        except Exception as e:
            logger.error(f"Error sending Gmail message: {e}")
            raise GoogleAPIError("Failed to send Gmail message")

    def _create_message(self, sender: str, to: str, subject: str, body: str, html: bool) -> Dict:
        """Create Gmail message object"""
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        import base64

        message = MIMEMultipart()
        message['to'] = to
        message['from'] = sender
        message['subject'] = subject

        msg = MIMEText(body, 'html' if html else 'plain')
        message.attach(msg)

        return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

#----------------------------------------------#
#              google_calendar                 #
#----------------------------------------------#
class CalendarService:
    """Calendar service wrapper"""
    def __init__(self, credentials_dict: Dict):
        self.service = get_google_service('calendar', credentials_dict)

    def list_events(self, calendar_id: str = 'primary', 
                   time_min: datetime = None, 
                   max_results: int = 10) -> List[Dict]:
        """List calendar events"""
        try:
            if not time_min:
                time_min = datetime.utcnow()

            events_result = self.service.events().list(
                calendarId=calendar_id,
                timeMin=time_min.isoformat() + 'Z',
                maxResults=max_results,
                singleEvents=True,
                orderBy='startTime'
            ).execute()
            return events_result.get('items', [])
        except Exception as e:
            logger.error(f"Error listing calendar events: {e}")
            raise GoogleAPIError("Failed to list calendar events")

    def create_event(self, summary: str, start_time: datetime, 
                    end_time: datetime, description: str = None, 
                    location: str = None, attendees: List[str] = None) -> Dict:
        """Create a calendar event"""
        try:
            event = {
                'summary': summary,
                'start': {'dateTime': start_time.isoformat()},
                'end': {'dateTime': end_time.isoformat()}
            }
            if description:
                event['description'] = description
            if location:
                event['location'] = location
            if attendees:
                event['attendees'] = [{'email': email} for email in attendees]

            return self.service.events().insert(
                calendarId='primary',
                body=event
            ).execute()
        except Exception as e:
            logger.error(f"Error creating calendar event: {e}")
            raise GoogleAPIError("Failed to create calendar event")

#----------------------------------------------#
#                 google_tasks                 #
#----------------------------------------------#
class TasksService:
    """Tasks service wrapper"""
    def __init__(self, credentials_dict: Dict):
        self.service = get_google_service('tasks', credentials_dict)

    def list_tasklists(self) -> List[Dict]:
        """List all task lists"""
        try:
            results = self.service.tasklists().list().execute()
            return results.get('items', [])
        except Exception as e:
            logger.error(f"Error listing task lists: {e}")
            raise GoogleAPIError("Failed to list task lists")

    def create_tasklist(self, title: str) -> Dict:
        """Create a new task list"""
        try:
            return self.service.tasklists().insert(body={'title': title}).execute()
        except Exception as e:
            logger.error(f"Error creating task list: {e}")
            raise GoogleAPIError("Failed to create task list")

    def list_tasks(self, tasklist_id: str) -> List[Dict]:
        """List tasks in a task list"""
        try:
            results = self.service.tasks().list(tasklist=tasklist_id).execute()
            return results.get('items', [])
        except Exception as e:
            logger.error(f"Error listing tasks: {e}")
            raise GoogleAPIError("Failed to list tasks")

    def create_task(self, tasklist_id: str, title: str, 
                   notes: str = None, due: datetime = None) -> Dict:
        """Create a new task"""
        try:
            task = {'title': title}
            if notes:
                task['notes'] = notes
            if due:
                task['due'] = due.isoformat() + 'Z'

            return self.service.tasks().insert(
                tasklist=tasklist_id,
                body=task
            ).execute()
        except Exception as e:
            logger.error(f"Error creating task: {e}")
            raise GoogleAPIError("Failed to create task")

#----------------------------------------------#
#                  google_keep                 #
#----------------------------------------------#
class KeepService:
    """Keep service wrapper"""
    def __init__(self, token: Dict):
        if not isinstance(token, dict) or 'token' not in token:
            raise GoogleAPIError("Invalid token format")

        self.headers = {
            'Authorization': f"Bearer {token['token']}",
            'Content-Type': 'application/json',
        }
        self.base_url = 'https://keep.googleapis.com/v1/'

    def list_notes(self) -> List[Dict]:
        """Retrieve all notes"""
        try:
            response = requests.get(f"{self.base_url}notes", headers=self.headers)
            response.raise_for_status()
            return response.json().get('notes', [])
        except Exception as e:
            logger.error(f"Error listing notes: {e}")
            raise GoogleAPIError("Failed to list notes")

    def get_note(self, note_id: str) -> Dict:
        """Retrieve a specific note"""
        try:
            response = requests.get(f"{self.base_url}notes/{note_id}", headers=self.headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error getting note: {e}")
            raise GoogleAPIError("Failed to get note")

    def create_note(self, data: Dict) -> Dict:
        """Create a new note"""
        try:
            response = requests.post(f"{self.base_url}notes", headers=self.headers, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error creating note: {e}")
            raise GoogleAPIError("Failed to create note")

    def update_note(self, note_id: str, data: Dict) -> Dict:
        """Update an existing note"""
        try:
            response = requests.patch(
                f"{self.base_url}notes/{note_id}",
                headers=self.headers,
                json=data
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error updating note: {e}")
            raise GoogleAPIError("Failed to update note")

    def delete_note(self, note_id: str) -> Dict:
        """Delete a note"""
        try:
            response = requests.delete(f"{self.base_url}notes/{note_id}", headers=self.headers)
            response.raise_for_status()
            return {'message': 'Note deleted'}
        except Exception as e:
            logger.error(f"Error deleting note: {e}")
            raise GoogleAPIError("Failed to delete note")

#----------------------------------------------#
#               token_services                 #
#----------------------------------------------#
def should_refresh_token(token_timestamp: datetime = None) -> bool:
    """
    Check if token should be refreshed based on timestamp
    
    Args:
        token_timestamp: Timestamp when token was last refreshed
        
    Returns:
        bool: True if token should be refreshed, False otherwise
    """
    if not token_timestamp:
        return True
    
    # Token expires in 1 hour, refresh if less than 5 minutes remain
    expiry_threshold = datetime.utcnow() - timedelta(minutes=55)
    return token_timestamp < expiry_threshold

def refresh_google_token(credentials_dict: Dict) -> Dict:
    """
    Refresh Google OAuth token if expired
    
    Args:
        credentials_dict: Dictionary containing OAuth credentials
        
    Returns:
        Dict: Updated credentials dictionary
        
    Raises:
        GoogleAPIError: If token refresh fails
    """
    try:
        # Check if token needs refreshing
        token_timestamp = credentials_dict.get('token_timestamp')
        if token_timestamp and isinstance(token_timestamp, str):
            token_timestamp = datetime.fromisoformat(token_timestamp.replace('Z', '+00:00'))
        
        if not should_refresh_token(token_timestamp):
            return credentials_dict

        # Refresh the token
        creds = credentials.Credentials(**credentials_dict)
        request = google.auth.transport.requests.Request()
        
        creds.refresh(request)
        
        # Return updated credentials
        return {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes,
            'token_timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        raise GoogleAPIError("Failed to refresh Google token")

def revoke_google_token(token: str) -> bool:
    """
    Revoke Google OAuth token
    
    Args:
        token: Token to revoke
        
    Returns:
        bool: True if revocation successful, False otherwise
    """
    try:
        # Use Google's token revocation endpoint
        revoke_uri = "https://oauth2.googleapis.com/revoke"
        response = requests.post(
            revoke_uri,
            params={'token': token},
            headers={'content-type': 'application/x-www-form-urlencoded'}
        )
        response.raise_for_status()
        return True
    except Exception as e:
        logger.error(f"Token revocation failed: {str(e)}")
        return False
