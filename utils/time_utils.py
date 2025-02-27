# ------------------------------------------------------------
# utils/time_utils.py
# ------------------------------------------------------------
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def timeago(timestamp):
    """
    Return a human-readable string indicating the time elapsed since the given timestamp.
    """
    now = datetime.utcnow()
    diff = now - timestamp

    if diff.days > 0:
        return f"{diff.days} days ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return "Just now"

def generate_timestamp():
    """
    Generate current UTC timestamp.
    """
    return datetime.utcnow()

def format_datetime(dt):
    """
    Format datetime object to string.
    """
    return dt.isoformat()

def parse_datetime(dt_string):
    """
    Parse datetime string to datetime object.
    """
    return datetime.fromisoformat(dt_string)
