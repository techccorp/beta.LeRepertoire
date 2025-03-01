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
from PIL import Image
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
        
        # For images: create thumbnail version
        if file_ext.lower() in IMAGE_EXTENSIONS:
            try:
                if use_gridfs:
                    # For GridFS, need to read the file back
                    file_obj = fs.get(file_id)
                    img_data = file_obj.read()
                    thumb_data = resize_image(BytesIO(img_data), (300, 300))
                    
                    # Store thumbnail in GridFS
                    thumb_filename = f"{new_filename.rsplit('.', 1)[0]}_thumb.{file_ext}"
                    thumb_id = fs.put(
                        thumb_data.getvalue(),
                        filename=thumb_filename,
                        content_type=mime_type,
                        metadata={'original_file_id': file_id, 'is_thumbnail': True}
                    )
                    
                    result['thumbnail_id'] = str(thumb_id)
                    result['thumbnail_url'] = url_for('get_image', filename=thumb_filename, _external=True)
                else:
                    # For filesystem storage
                    thumb_path = os.path.join(upload_dir, f"{new_filename.rsplit('.', 1)[0]}_thumb.{file_ext}")
                    create_thumbnail(file_path, thumb_path)
                    result['thumbnail_path'] = thumb_path
                    result['thumbnail_url'] = url_for('get_image', filename=os.path.basename(thumb_path), _external=True)
            except Exception as e:
                logger.warning(f"Thumbnail creation failed: {str(e)}")
                # Continue even if thumbnail creation fails
        
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
            
            # Check for and delete thumbnail
            try:
                # Extract base filename without extension
                if '.' in filename:
                    base_filename = filename.rsplit('.', 1)[0]
                    ext = filename.rsplit('.', 1)[1]
                    thumb_filename = f"{base_filename}_thumb.{ext}"
                    
                    # Look for thumbnail
                    thumb_file = fs.find_one({'filename': thumb_filename})
                    if thumb_file:
                        fs.delete(thumb_file._id)
                        logger.info(f"Deleted thumbnail from GridFS: {thumb_filename}")
                    
                    # Also look for thumbnail by metadata
                    thumb_by_meta = fs.find_one({'metadata.original_file_id': file_id})
                    if thumb_by_meta:
                        fs.delete(thumb_by_meta._id)
                        logger.info(f"Deleted thumbnail by metadata reference from GridFS")
            except Exception as e:
                logger.warning(f"Error deleting thumbnail: {str(e)}")
                # Continue even if thumbnail deletion fails
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
                
                # Check for and delete thumbnail
                try:
                    if '.' in file_path:
                        base_path = file_path.rsplit('.', 1)[0]
                        ext = file_path.rsplit('.', 1)[1]
                        thumb_path = f"{base_path}_thumb.{ext}"
                        
                        if os.path.exists(thumb_path):
                            os.remove(thumb_path)
                            logger.info(f"Deleted thumbnail from filesystem: {thumb_path}")
                except Exception as e:
                    logger.warning(f"Error deleting thumbnail: {str(e)}")
                    # Continue even if thumbnail deletion fails
            
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
    Resize an image to the specified size.
    
    Args:
        image_stream: Image file stream or path
        size (tuple): Target size as (width, height)
        format (str, optional): Output format. Defaults to None (same as input).
        quality (int, optional): JPEG quality (1-100). Defaults to 85.
        
    Returns:
        BytesIO: Resized image stream
        
    Raises:
        ValidationError: If image processing fails
    """
    try:
        # Open the image
        if isinstance(image_stream, str):
            # If a file path is provided
            img = Image.open(image_stream)
        else:
            # If a file stream is provided
            img = Image.open(image_stream)
        
        # Convert to RGB if RGBA to avoid issues with JPEG
        if img.mode == 'RGBA' and (not format or format.lower() == 'jpeg' or format.lower() == 'jpg'):
            img = img.convert('RGB')
        
        # Resize the image while preserving aspect ratio
        img.thumbnail(size, Image.LANCZOS)
        
        # Save to BytesIO
        output = BytesIO()
        
        # Get format from original if not specified
        if not format:
            format = img.format if img.format else 'JPEG'
        
        # Save with specified format and quality
        img.save(output, format=format, quality=quality)
        
        # Reset the file pointer to the beginning
        output.seek(0)
        
        return output
        
    except Exception as e:
        logger.error(f"Image resizing failed: {str(e)}")
        raise ValidationError(f"Image resizing failed: {str(e)}")

def create_thumbnail(input_path, output_path=None, size=(300, 300), quality=85):
    """
    Generate thumbnail version for an image.
    
    Args:
        input_path (str): Path to source image
        output_path (str, optional): Path to save thumbnail. Defaults to None (auto-generated).
        size (tuple, optional): Thumbnail size. Defaults to (300, 300).
        quality (int, optional): JPEG quality (1-100). Defaults to 85.
        
    Returns:
        str: Path to generated thumbnail
        
    Raises:
        ValidationError: If thumbnail creation fails
    """
    try:
        # Generate output path if not provided
        if not output_path:
            if '.' in input_path:
                base_path = input_path.rsplit('.', 1)[0]
                ext = input_path.rsplit('.', 1)[1]
                output_path = f"{base_path}_thumb.{ext}"
            else:
                output_path = f"{input_path}_thumb"
        
        # Create parent directory if needed
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        
        # Open and resize the image
        with Image.open(input_path) as img:
            # Convert to RGB if RGBA to avoid issues with JPEG
            if img.mode == 'RGBA' and output_path.lower().endswith(('jpg', 'jpeg')):
                img = img.convert('RGB')
                
            # Resize the image while preserving aspect ratio
            img.thumbnail(size, Image.LANCZOS)
            
            # Save the thumbnail
            img.save(output_path, quality=quality)
        
        return output_path
        
    except Exception as e:
        logger.error(f"Thumbnail creation failed: {str(e)}")
        raise ValidationError(f"Thumbnail creation failed: {str(e)}")
