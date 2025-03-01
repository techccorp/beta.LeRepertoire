# -------------------------------------#
#               /app.py
# -------------------------------------#
import os
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory, Response, send_file, g
from pymongo import MongoClient
from flask_cors import CORS
from pymongo.errors import ConnectionFailure
from bson.json_util import dumps
from bson.objectid import ObjectId
from dotenv import load_dotenv
import logging
from flask_wtf.csrf import CSRFProtect
from BunnyCDN.Storage import Storage
from BunnyCDN.CDN import CDN
from werkzeug.utils import secure_filename
from datetime import datetime
from io import BytesIO
import gridfs
import json
import requests
from authlib.integrations.flask_client import OAuth

# Import from utils package - maintaining original imports
from utils import (
    # Authentication
    validate_payroll_id,
    hash_password,
    check_password,
    SessionManager,
    SessionExpiredError,
    AuthManager,
    login_required,
    require_permission,
    admin_required,
    api_key_required,
    
    # Allergen Management
    lookup_allergen,
    get_allergen_by_id,
    create_allergen,
    update_allergen,
    delete_allergen,
    search_allergens,
    validate_allergen_data,
    AllergenError,
    
    # Recipe and Search
    lookup_ingredient,
    lookup_tag,
    lookup_cuisine,
    lookup_method,
    lookup_dietary,
    lookup_mealtype,
    lookup_recipeIngredient,
    lookup_globalRecipe,
    
    # Time Management
    timeago,
    generate_timestamp,
    format_datetime,
    parse_datetime,
    
    # Note Management
    create_user_note,
    get_user_notes,
    get_user_note_by_id,
    update_user_note,
    delete_user_note,
    
    # Business Management
    lookup_business,
    lookup_venue,
    lookup_work_area,
    create_business,
    add_venue_to_business,
    add_work_area_to_venue,
    assign_user_to_business,
    assign_user_to_work_area,
    get_business_hierarchy,
    update_business_status,
    validate_business_structure,
    
    # Google Integration
    validate_google_token,
    get_google_service,
    KeepService,
    
    # Security
    generate_random_string,
    generate_secure_token,
    generate_id_with_prefix,
    hash_string,
    constant_time_compare,
    generate_session_id,
    sanitize_input,
    log_security_event,
    
    # Validation
    validate_request_data,
    validate_id_format,
    validate_uuid,
    validate_email,
    validate_date_format,
    validate_phone_number,
    validate_required_fields,
    validate_field_length,
    validate_numeric_range,
    validate_business_data,
    validate_venue_data,
    validate_work_area_data,
    
    # Database
    safe_object_id,
    format_mongo_doc,
    create_mongo_query,
    handle_mongo_error,
    sanitize_mongo_query,
    build_aggregation_pipeline,
    update_timestamp_fields,
    get_collection_stats,
    ensure_indexes,
    bulk_write_operations,
    get_distinct_values,
    execute_transaction,
    get_db,
    close_db,
    get_company_config,
    get_venue_details,
    get_user_details,
    get_workplace_config,
    
    # Payroll
    calculate_tax,
    calculate_period_amounts,
    calculate_ytd_amounts,
    get_user_ytd_amounts,
    calculate_service_period,
    calculate_leave_accrual,
    get_leave_summary,
    get_user_leave_summary,
    map_user_leave_data,
    
    # Error Handling
    AppError,
    ValidationError,
    AuthenticationError,
    PermissionError,
    NotFoundError,
    DatabaseError,
    handle_error,
    log_error,
    format_error_response,
    validate_or_raise,
    assert_found,
    assert_valid,
    assert_permitted,
    get_error_context,
    
    # Logging
    CustomJSONFormatter,
    setup_logging,
    log_event,
    log_api_request,
    log_security_event,
    cleanup_logs,
    get_log_stats,
    AuditLogger,
    
    # Request Processing
    get_request_data,
    validate_request_data,
    format_response,
    paginate_results,
    parse_query_params,
    validate_content_type,
    rate_limit,
    log_request_info,
    get_client_ip,
    get_pagination_params,
    get_sort_params,
    get_filter_params,
    validate_request_size,
    
    # Session Management
    create_session,
    get_session,
    delete_session,
    refresh_session,
    validate_session,
    get_user_from_session,
    set_user_in_session,
    
    # User Management
    create_user,
    get_user_by_id,
    update_user,
    delete_user,
    get_all_users,
    validate_user_data,
    authenticate_user,
    get_user_roles,
    assign_role_to_user,
    remove_role_from_user,
    
    # Notification
    send_email_notification,
    send_sms_notification,
    create_notification,
    get_notifications_for_user,
    mark_notification_as_read,
    delete_notification,
    
    # File Management
    upload_file,
    delete_file,
    get_file_url,
    validate_file_type,
    resize_image,
    generate_file_name,
    
    # Caching
    set_cache,
    get_cache,
    delete_cache,
    clear_cache,
    cache_key_generator,
    
    # Analytics
    track_event,
    log_user_activity,
    generate_report,
    get_user_engagement_data,
    analyze_trends,
    
    # Payment Processing
    process_payment,
    refund_payment,
    validate_payment_info,
    get_payment_status,
    create_payment_intent,
    
    # API Integration
    call_external_api,
    handle_api_response,
    authenticate_api_request,
    log_api_usage,
    validate_api_key,
    
    # Configuration
    load_config,
    save_config,
    validate_config,
    get_config_value,
    set_config_value,
    
    # Miscellaneous
    generate_slug,
    format_currency,
    parse_json,
    format_json,
    get_current_timestamp
)

# Import configuration and services
from config import Config, GoogleOAuthConfig, GoogleOAuthConfigError
from services import get_service
id_service = get_service('id_service')
from models import get_db as models_get_db, get_search_db

# -------------------------------------#
#        Initialize logging
# -------------------------------------#
logging.basicConfig(level=Config.LOG_LEVEL)
logger = logging.getLogger(__name__)

# ----------------------------------------------------#
#      Load environment variables from .env file
#-----------------------------------------------------#
load_dotenv()
logger.info("Environment variables loaded successfully")

# -------------------------------------#
#        Initialize Flask app
# -------------------------------------#
app = Flask(__name__, static_folder="static", static_url_path="/static")

# Verify static folder exists
if not os.path.exists(app.static_folder):
    os.makedirs(app.static_folder, exist_ok=True)
    logger.info(f"Created static folder: {app.static_folder}")

# -------------------------------------#
#     Application Configuration
# -------------------------------------#
app.config.from_object(Config)
app.config['SECRET_KEY'] = Config.SECRET_KEY

# Validate secret key in production
if app.config['SECRET_KEY'] == 'a_secure_random_key' and not app.config.get('DEBUG', False):
    logger.critical("Default secret key detected in production! This is a security risk.")
    raise RuntimeError("Cannot use default secret key in production")

# -------------------------------------#
#     Initialize CSRF protection
# -------------------------------------#
csrf = CSRFProtect(app)

# -------------------------------------#
#          Initialize CORS
# -------------------------------------#
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "X-CSRF-Token"]
    }
})

# -------------------------------------#
#    MongoDB client initialization
# -------------------------------------#
try:
    client = MongoClient(Config.MONGO_URI)
    app.config['MONGO_CLIENT'] = client
    db = client[Config.MONGO_DBNAME]  # Database reference
    app.mongo = type('MongoProxy', (), {'db': db, 'client': client})  # Create a proxy for app.mongo.db access

    # -------------------------------------#
    #        Test database connection
    # -------------------------------------#
    client.admin.command('ping')
    logger.info("MongoDB connection established successfully")
except Exception as e:
    logger.critical(f"Failed to connect to MongoDB: {str(e)}")
    raise

# -------------------------------------#
#        Initialize GridFS bucket
# -------------------------------------#
try:
    fs = gridfs.GridFS(db, collection=Config.GRIDFS_BUCKET_NAME)
    app.config['fs'] = fs  # Make GridFS available globally
    logger.info("GridFS initialized successfully")
except Exception as e:
    logger.critical(f"Failed to initialize GridFS: {str(e)}")
    raise

# -------------------------------------#
#  Initialize IDService
# -------------------------------------#
try:
    id_service = IDService(db)
    app.config['ID_SERVICE'] = id_service  # Make IDService available globally
    logger.info("ID Service initialized successfully")
except Exception as e:
    logger.critical(f"Failed to initialize ID Service: {str(e)}")
    raise

# -------------------------------------#
# Define a Custom JSON Encoder
# -------------------------------------#
class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(JSONEncoder, self).default(obj)

# -------------------------------------#
#     Set the custom JSON encoder
# -------------------------------------#
app.json_encoder = JSONEncoder

# -------------------------------------#
# Initialize Google OAuth
# -------------------------------------#
try:
    # Initialize OAuth
    oauth = OAuth(app)
    
    # Configure Google OAuth 
    try:
        GoogleOAuthConfig.validate_config()
        
        # Register Google OAuth with Authlib
        google = oauth.register(
            name='google',
            client_id=GoogleOAuthConfig.GOOGLE_CLIENT_ID,
            client_secret=GoogleOAuthConfig.GOOGLE_CLIENT_SECRET,
            server_metadata_url=GoogleOAuthConfig.GOOGLE_DISCOVERY_URL,
            client_kwargs={
                'scope': ' '.join(GoogleOAuthConfig.GOOGLE_SCOPES)
            }
        )
        
        # Store in app for easy access
        app.google = google
        logger.info("Google OAuth initialized successfully")
    except GoogleOAuthConfigError as e:
        if app.config.get('DEBUG', False):
            logger.warning(f"Google OAuth not configured properly: {str(e)}")
            # Create a mock for development to prevent errors
            from unittest.mock import MagicMock
            app.google = MagicMock()
            logger.info("Using mock Google OAuth client for development")
        else:
            raise
except Exception as e:
    logger.critical(f"Failed to initialize OAuth: {str(e)}")
    raise

# -------------------------------------#
# Initialize Session and Permission Management
# -------------------------------------#
try:
    # Initialize session manager
    session_manager = SessionManager(app)
    app.session_manager = session_manager
    logger.info("Session Manager initialized successfully")
    
    # Try to initialize the permission manage
    try:
        # First try to find a permission manager initialization function
        # This flexible approach maintains compatibility
        permission_manager = None
        
        # Try to import from modules directly (original approach)
        try:
            from modules.permissionsManager_module import init_permission_manager
            permission_manager = init_permission_manager(app)
            logger.info("Permission Manager initialized from modules package")
        except (ImportError, AttributeError) as e:
            logger.info(f"Permission Manager not available in modules package: {str(e)}")
            
            # Fallback to utils if available
            try:
                # Define a local function to initialize permissions if needed
                def init_permission_manager_from_utils(app):
                    """Initialize permission manager from available utils components"""
                    # Use existing components to build permission manager functionality
                    # This is a placeholder for custom initialization logic
                    from utils import PermissionError
                    return app.config.get('permission_manager', None)
                
                permission_manager = init_permission_manager_from_utils(app)
                if permission_manager:
                    logger.info("Permission Manager initialized from utils package")
            except Exception as e:
                logger.info(f"Permission Manager not available in utils package: {str(e)}")
        
        # Store permission manager if initialized
        if permission_manager:
            app.permission_manager = permission_manager
            logger.info("Permission Manager registered with application")
        else:
            logger.info("No Permission Manager available, skipping initialization")
            
    except Exception as e:
        logger.warning(f"Could not initialize Permission Manager: {str(e)}")
except Exception as e:
    logger.critical(f"Failed to initialize authentication systems: {str(e)}")
    raise

# -------------------------------------#
#        Register routes
# -------------------------------------#
try:
    # Import route registration functions
    from routes import register_routes
    register_routes(app)
    logger.info("Routes registered successfully")
except Exception as e:
    logger.critical(f"Failed to register routes: {str(e)}")
    raise

# -------------------------------------#
#        Import blueprints
# -------------------------------------#
from routes.auth_routes import auth
from routes.allergen_routes import allergens
from routes.home_routes import home
from routes.error_routes import error_routes
from routes.finance_routes import finance
from routes.common_routes import common
from routes.google_routes import google_api
from routes.employment_routes import employment
from routes.product_routes import products
from routes.recipeSearch_routes import recipe_search
from routes.googleTasks_routes import google_tasks
from routes.notes_routes import notes
from routes.resource_routes import resource
from routes.businessUsers_routes import business_users
from routes.business.routes import business
from routes.payroll_routes import payroll
from modules import module_manager

# -------------------------------------#
#         Register blueprints
# -------------------------------------#
blueprints = [
    (auth, "auth"),
    (allergens, "allergens"),
    (home, "home"),
    (error_routes, "error_routes"),
    (finance, "finance_routes"),
    (common, "common_routes"),
    (employment, "employment_routes"),
    (google_api, "google_routes"),
    (products, "product_routes"),
    (recipe_search, "recipe_search"),
    (google_tasks, "google_tasks_routes"),
    (notes, "notes_routes"),
    (resource, "resource_routes"),
    (business_users, "businessUser _routes"),
    (business, "business_routes"),
    (payroll, "payroll_routes")
]

for bp, name in blueprints:
    try:
        app.register_blueprint(bp)
        logger.info(f"{name} blueprint initialized successfully")
    except Exception as e:
        logger.error(f"Failed to register {name} blueprint: {str(e)}")
        if not app.config.get('DEBUG', False):
            raise

# -------------------------------------#
#           Initialize modules
# -------------------------------------#
try:
    module_manager.init_app(app)
    logger.info("Module system initialized successfully")
except Exception as e:
    logger.critical(f"Failed to initialize module system: {str(e)}")
    raise

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    redirect_uri = app.config.get('REDIRECT_URI', GoogleOAuthConfig.GOOGLE_REDIRECT_URI)
    return app.google.authorize_redirect(redirect_uri)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/login/authorized')
def authorized():
    try:
        token = app.google.authorize_access_token()
        resp = app.google.get('userinfo')
        user_info = resp.json()
        session['user'] = user_info
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Error in OAuth callback: {str(e)}")
        return redirect(url_for('index'))

@app.route('/login/google', methods=['POST'])
def login_google():
    token = request.json.get('id_token')
    if token:
        try:
            # Verify token with Google
            user_info = validate_google_token(token)
            if user_info:
                session['user'] = user_info
                return jsonify(success=True, redirect_url=url_for('index'))
            return jsonify(success=False, message='Invalid token.')
        except Exception as e:
            logger.error(f"Error validating Google token: {str(e)}")
            return jsonify(success=False, message='Error validating token.')
    return jsonify(success=False, message='Token is required.')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

@app.route('/image/<filename>', methods=['GET'])
def get_image(filename):
    try:
        # Sanitize filename to prevent path traversal
        filename = secure_filename(filename)
        
        file = fs.find_one({'filename': filename})
        
        if file:
            return send_file(
                BytesIO(file.read()), 
                mimetype=file.content_type or 'image/jpeg',
                download_name=filename
            )
        
        file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        
        if os.path.exists(file_path):
            return send_from_directory(Config.UPLOAD_FOLDER, filename)
        
        logger.warning(f"Image not found: {filename}")
        return "Image not found", 404

    except Exception as e:
        logger.error(f"Error fetching image {filename}: {str(e)}")
        return str(e), 500

@app.route('/upload', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    
    if file.filename == '':
        return 'No selected file', 400
    
    if not file or not allowed_file(file.filename):
        return 'Invalid file type', 400
    
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = secure_filename(f"{timestamp}_{file.filename}")
        
        file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        file.save(file_path)

        fs.put(
            file, 
            filename=filename, 
            content_type=file.content_type
        )
        
        logger.info(f"File {filename} successfully uploaded to both disk and GridFS")
        return jsonify({
            'status': 'success',
            'message': 'File successfully uploaded',
            'filename': filename
        }), 200
        
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Error uploading file: {str(e)}"
        }), 500

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS
           
@app.route('/api/beef-cuts', methods=['GET'])
def get_beef_cuts():
    """API endpoint to retrieve data from the 'meatspace' collection."""
    try:
        # Fetch data from the 'meatspace' collection
        meatspace_data = list(db[Config.COLLECTION_MEATSPACE].find({}))
        return jsonify(json.loads(dumps(meatspace_data))), 200
    except Exception as e:
        logger.error(f"Error fetching data from 'meatspace': {str(e)}")
        return jsonify({'error': 'Failed to retrieve data'}), 500

@app.errorhandler(404)
def page_not_found(e):
    logger.warning("404 error: Page not found")
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 error: {str(e)}")
    return render_template('errors/500.html'), 500

@app.before_request
def before_request():
    g.start_time = datetime.utcnow()
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    g.request_id = id_service.generate_request_id()

@app.teardown_appcontext
def teardown_db(exception):
    if hasattr(g, 'mongo_client'):
        g.mongo_client.close()
    
    # Close database connections from utils
    close_db(exception)

def create_app(config_object=None):
    if config_object:
        app.config.from_object(config_object)
    return app

if __name__ == '__main__':
    app = create_app(Config)
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        ssl_context=Config.SSL_CONTEXT if Config.USE_SSL else None
    )
