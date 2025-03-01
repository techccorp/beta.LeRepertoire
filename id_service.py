# ------------------------------------------------------------
# id_service.py (Compatibility Module)
# ------------------------------------------------------------
"""
Compatibility module for ID Service.
Maintains backward compatibility with existing import statements.
"""
import logging
import warnings

# Import the actual implementation from services
from services.id_service import IDService

# Initialize module-level logger
logger = logging.getLogger(__name__)

# Issue deprecation warning
warnings.warn(
    "Importing IDService from root module is deprecated. "
    "Use 'from services import IDService' instead.",
    DeprecationWarning,
    stacklevel=2
)

# Export the IDService class
__all__ = ['IDService']
