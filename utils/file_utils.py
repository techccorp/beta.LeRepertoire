"""
File management utilities for secure uploads and processing.
Production-ready implementation with error handling.
"""
import os
import uuid
import logging
import mimetypes
from datetime import datetime
from werkzeug.utils import secure_filename
from io import BytesIO
from flask import current_app, url_for
from gridfs import GridFS
from bson.objectid import ObjectId
from pymongo.errors import PyMongoError

# Import error utilities for consistent error handling
from .error_utils import ValidationError, NotFoundError, DatabaseError, AppError

# Default allowed extensions for production safety
DEFAULT_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv', 'txt'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

logger = logging.getLogger(__name__)

def generate_file_name(original_filename):
    """
    Generate a unique filename based on timestamp and UUID.
    
    Args:
        original_filename (str): Original filename to preserve extension
        
    Returns:
        tuple: (secure_filename, extension)
    """
    # Secure the filename to prevent path traversal
    secure_name = secure_filename(original_filename)
    
    # Get the file extension
    if '.' in secure_name:
        file_ext = secure_name.rsplit('.', 1)[1].lower()
    else:
        file_ext = ''
    
    # Generate a unique name with timestamp and UUID
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    unique_id = uuid.uuid4().hex
    new_filename = f"{timestamp}_{unique_id}"
    
    if file_ext:
        new_filename = f"{new_filename}.{file_ext}"
    
    return new_filename, file_ext

def validate_file_type(filename, allowed_extensions=None):
    """
    Validate if the file type is allowed.
    
    Args:
        filename (str): Filename to validate
        allowed_extensions (set, optional): Set of allowed extensions. Defaults to None.
        
    Returns:
        bool: True if file type is allowed, False otherwise
    """
    if allowed_extensions is None:
        allowed_extensions = DEFAULT_ALLOWED_EXTENSIONS
    
    if '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in allowed_extensions

def upload_file(file_stream, allowed_extensions=None, upload_dir=None, max_size=MAX_FILE_SIZE, use_gridfs=True, metadata=None):
    """
    Secure file upload handler with production-grade validation.
    
    Args:
        file_stream: File stream object (e.g., request.files['file'])
        allowed_extensions (set, optional): Set of allowed extensions. Defaults to None.
        upload_dir (str, optional): Directory to upload to if not using GridFS. Defaults to None.
        max_size (int, optional): Maximum file size in bytes. Defaults to MAX_FILE_SIZE.
        use_gridfs (bool, optional): Whether to use GridFS for storage. Defaults to True.
        metadata (dict, optional): Additional file metadata. Defaults to None.
        
    Returns:
        dict: File information including filename, path or id, and URL
        
    Raises:
        ValidationError: If file validation fails
        DatabaseError: If database storage fails
        AppError: For other errors
    """
    try:
        # Validate input
        if not file_stream or not hasattr(file_stream, 'filename') or file_stream.filename == '':
            raise ValidationError("No file provided")
        
        # Check file size
        file_stream.seek(0, os.SEEK_END)
        size = file_stream.tell()
        file_stream.seek(0)  # Reset file position
        
        if size > max_size:
            raise ValidationError(f"File size exceeds maximum allowed {max_size/1024/1024}MB")
        
        # Set defaults
        allowed_extensions = allowed_extensions or DEFAULT_ALLOWED_EXTENSIONS
        
        # Get the original filename
        original_filename = file_stream.filename
        
        # Validate file type
        if not validate_file_type(original_filename, allowed_extensions):
            raise ValidationError(f"Invalid file type. Allowed types: {', '.join(allowed_extensions)}")
        
        # Generate a unique filename
        new_filename, file_ext = generate_file_name(original_filename)
        
        # Determine mime type
        mime_type = get_mime_type(new_filename)
        
        # Prepare metadata
        file_metadata = {
            'original_filename': original_filename,
            'filename': new_filename,
            'content_type': mime_type,
            'size': size,
            'upload_date': datetime.utcnow(),
            'user_id': metadata.get('user_id') if metadata else None
        }
        
        # Add any additional metadata
        if metadata:
            file_metadata.update(metadata)
        
        result = {}
        
        if use_gridfs:
            # Store in GridFS
            try:
                db = current_app.mongo.db
                fs = GridFS(db)
                
                # Store the file in GridFS
                file_id = fs.put(
                    file_stream,
                    filename=new_filename,
                    content_type=mime_type,
                    metadata=file_metadata
                )
                
                # Update result with GridFS info
                result = {
                    'file_id': str(file_id),
                    'filename': new_filename,
                    'original_filename': original_filename,
                    'content_type': mime_type,
                    'size': size,
                    'url': url_for('get_image', filename=new_filename, _external=True)
                }
                
                # Store file metadata in a separate collection for easier querying
                db.file_metadata.insert_one({
                    'file_id': file_id,
                    **file_metadata
                })
                
                logger.info(f"File uploaded to GridFS: {new_filename} (ID: {file_id})")
                
            except PyMongoError as e:
                logger.error(f"Database error storing file in GridFS: {str(e)}")
                raise DatabaseError(f"Failed to store file: {str(e)}")
        else:
            # Store on filesystem
            if not upload_dir:
                upload_dir = current_app.config.get('UPLOAD_FOLDER', '/var/www/uploads')
            
            # Ensure upload directory exists
            os.makedirs(upload_dir, exist_ok=True)
            
            # Full path to save the file
            file_path = os.path.join(upload_dir, new_filename)
            
            # Save the file
            file_stream.save(file_path)
            
            # Store file metadata in database
            try:
                db = current_app.mongo.db
                metadata_id = db.file_metadata.insert_one({
                    'file_path': file_path,
                    **file_metadata
                }).inserted_id
                
                result = {
                    'metadata_id': str(metadata_id),
                    'filename': new_filename,
                    'original_filename': original_filename,
                    'content_type': mime_type,
                    'size': size,
                    'path': file_path,
                    'url': url_for('get_image', filename=new_filename, _external=True)
                }
                
                logger.info(f"File uploaded to filesystem: {file_path}")
                
            except PyMongoError as e:
                # If database fails but file was saved, delete the file
                if os.path.exists(file_path):
                    os.remove(file_path)
                logger.error(f"Database error storing file metadata: {str(e)}")
                raise DatabaseError(f"Failed to store file metadata: {str(e)}")
        
        return result
        
    except ValidationError:
        raise
    except DatabaseError:
        raise
    except Exception as e:
        logger.error(f"File upload failed: {str(e)}")
        raise AppError(f"File upload failed: {str(e)}")

def delete_file(file_id=None, filename=None, use_gridfs=True):
    """
    Delete a file from storage.
    
    Args:
        file_id (str, optional): ID of the file to delete. Defaults to None.
        filename (str, optional): Filename to delete if file_id not provided. Defaults to None.
        use_gridfs (bool, optional): Whether file is stored in GridFS. Defaults to True.
        
    Returns:
        bool: True if file was deleted successfully
        
    Raises:
        ValidationError: If neither file_id nor filename is provided
        NotFoundError: If file not found
        DatabaseError: If database operation fails
    """
    try:
        if not file_id and not filename:
            raise ValidationError("Either file_id or filename must be provided")
        
        db = current_app.mongo.db
        
        if use_gridfs:
            fs = GridFS(db)
            
            # Find the file by ID or filename
            if file_id:
                if isinstance(file_id, str) and ObjectId.is_valid(file_id):
                    file_id = ObjectId(file_id)
                
                if not fs.exists(file_id):
                    raise NotFoundError(f"File with ID {file_id} not found")
                
                # Get file metadata before deletion for thumbnail deletion
                file_metadata = db.file_metadata.find_one({'file_id': file_id})
                filename = fs.get(file_id).filename
                
                # Delete from GridFS
                fs.delete(file_id)
                
                # Delete metadata
                db.file_metadata.delete_one({'file_id': file_id})
                
                logger.info(f"Deleted file from GridFS: {filename} (ID: {file_id})")
            else:
                # Find by filename
                file = fs.find_one({'filename': filename})
                if not file:
                    raise NotFoundError(f"File with name {filename} not found")
                
                file_id = file._id
                
                # Delete from GridFS
                fs.delete(file_id)
                
                # Delete metadata
                db.file_metadata.delete_one({'file_id': file_id})
                
                logger.info(f"Deleted file from GridFS: {filename}")
        else:
            # File stored on filesystem
            if filename:
                # Find file metadata by filename
                file_metadata = db.file_metadata.find_one({'filename': filename})
            else:
                # Find file metadata by ID
                file_metadata = db.file_metadata.find_one({'_id': ObjectId(file_id)})
            
            if not file_metadata:
                raise NotFoundError(f"File metadata not found")
            
            # Get file path
            file_path = file_metadata.get('file_path')
            if not file_path or not os.path.exists(file_path):
                logger.warning(f"File not found on disk: {file_path}")
            else:
                # Delete file from filesystem
                os.remove(file_path)
                logger.info(f"Deleted file from filesystem: {file_path}")
            
            # Delete metadata
            if filename:
                db.file_metadata.delete_one({'filename': filename})
            else:
                db.file_metadata.delete_one({'_id': ObjectId(file_id)})
            
            logger.info(f"Deleted file metadata from database")
        
        return True
        
    except NotFoundError:
        raise
    except ValidationError:
        raise
    except PyMongoError as e:
        logger.error(f"Database error deleting file: {str(e)}")
        raise DatabaseError(f"Failed to delete file: {str(e)}")
    except Exception as e:
        logger.error(f"Error deleting file: {str(e)}")
        raise AppError(f"Failed to delete file: {str(e)}")

def get_file_url(file_id=None, filename=None, thumbnail=False):
    """
    Get URL for a file.
    
    Args:
        file_id (str, optional): ID of the file. Defaults to None.
        filename (str, optional): Filename if file_id not provided. Defaults to None.
        thumbnail (bool, optional): Whether to get thumbnail URL. Defaults to False.
        
    Returns:
        str: URL to access the file
        
    Raises:
        ValidationError: If neither file_id nor filename is provided
        NotFoundError: If file not found
        DatabaseError: If database operation fails
    """
    try:
        if not file_id and not filename:
            raise ValidationError("Either file_id or filename must be provided")
        
        db = current_app.mongo.db
        
        # Find file metadata
        if file_id:
            if isinstance(file_id, str) and ObjectId.is_valid(file_id):
                file_id = ObjectId(file_id)
            
            file_metadata = db.file_metadata.find_one({'file_id': file_id})
            if not file_metadata:
                raise NotFoundError(f"File with ID {file_id} not found")
                
            filename = file_metadata.get('filename')
        else:
            file_metadata = db.file_metadata.find_one({'filename': filename})
            if not file_metadata:
                raise NotFoundError(f"File with name {filename} not found")
        
        # Modify filename for thumbnail if requested
        if thumbnail:
            if '.' in filename:
                base_filename = filename.rsplit('.', 1)[0]
                ext = filename.rsplit('.', 1)[1]
                filename = f"{base_filename}_thumb.{ext}"
        
        # Generate URL
        url = url_for('get_image', filename=filename, _external=True)
        
        return url
        
    except NotFoundError:
        raise
    except ValidationError:
        raise
    except PyMongoError as e:
        logger.error(f"Database error getting file URL: {str(e)}")
        raise DatabaseError(f"Failed to get file URL: {str(e)}")
    except Exception as e:
        logger.error(f"Error getting file URL: {str(e)}")
        raise AppError(f"Failed to get file URL: {str(e)}")

def get_mime_type(filename):
    """
    Get MIME type from filename.
    
    Args:
        filename (str): Filename to get MIME type for
        
    Returns:
        str: MIME type or 'application/octet-stream' if not determined
    """
    mime_type, encoding = mimetypes.guess_type(filename)
    if mime_type is None:
        mime_type = 'application/octet-stream'
    return mime_type

def resize_image(image_stream, size, format=None, quality=85):
    """
    Placeholder for image resizing functionality.
    This function requires the PIL/Pillow library which is currently not available.
    
    Args:
        image_stream: Image file stream or path
        size (tuple): Target size as (width, height)
        format (str, optional): Output format. Defaults to None (same as input).
        quality (int, optional): JPEG quality (1-100). Defaults to 85.
        
    Returns:
        BytesIO: Original image stream
        
    Raises:
        ValidationError: If image processing fails
    """
    logger.warning("Image resizing is not available - PIL/Pillow library is missing")
    # Just return the original image
    if isinstance(image_stream, str):
        with open(image_stream, 'rb') as f:
            output = BytesIO(f.read())
            output.seek(0)
            return output
    return image_stream
