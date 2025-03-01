# --------------------------------------------------------#
#                   utils/__init__.py                     #
# --------------------------------------------------------#
"""
Utility modules for Le Repertoire application.
Provides centralized access to all utility functions and classes.
"""

# ---------------------------------------#
#     Authentication Utilities           #
# ---------------------------------------#
from .auth.auth_utils import (
    hash_password,
    check_password,
    validate_payroll_id
)

from .auth import (
    SessionManager,
    SessionExpiredError,
    AuthManager
)

from .auth.decorators import (
    login_required,
    require_permission,
    admin_required,
    api_key_required
)

# ---------------------------------------#
#     Allergen Management Utilities      #
# ---------------------------------------#
from .allergen_utils import (
    lookup_allergen,
    get_allergen_by_id,
    create_allergen,
    update_allergen,
    delete_allergen,
    search_allergens,
    validate_allergen_data,
    AllergenError
)

# ---------------------------------------#
#      Recipe and Search Utilities       #
# ---------------------------------------#    
from .recipe_utils import (
    lookup_ingredient,
    lookup_tag,
    lookup_cuisine,
    lookup_method,
    lookup_dietary,
    lookup_mealtype,
    lookup_recipeIngredient,
    lookup_globalRecipe
)

# ---------------------------------------#
#      Time Management Utilities         #
# ---------------------------------------#    
from .time_utils import (
    timeago,
    generate_timestamp,
    format_datetime,
    parse_datetime
)

# ---------------------------------------#
#       Note Management Utilities        #
# ---------------------------------------#    
from .notes_utils import (
    create_user_note,
    get_user_notes,
    get_user_note_by_id,
    update_user_note,
    delete_user_note
)

# ---------------------------------------#
#     Business Management Utilities      #
# ---------------------------------------#    
from .business_utils import (
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
    validate_business_structure
)

# ---------------------------------------#
#       Google Integration Utilities     #
# ---------------------------------------#    
from .google_utils import (
    validate_google_token,
    get_google_service,
    KeepService
)

# ---------------------------------------#
#          Defense Utilities             #
# ---------------------------------------#    
from .defense import (
    # Security
    generate_random_string,
    generate_secure_token,
    generate_id_with_prefix,
    hash_string,
    constant_time_compare,
    generate_session_id,
    sanitize_input,
    log_security_event,
    
    # Rate Limiting
    RateLimiter,
    
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
    validate_work_area_data
)

# ---------------------------------------#
#           Database Utilities           #
# ---------------------------------------#    
from .db_utils import (
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
    execute_transaction
)

# -----------------------------------#
#    Payroll Processing Utilities    #
# -----------------------------------#
from .payroll import (
    calculate_tax,
    calculate_period_amounts,
    calculate_ytd_amounts,
    get_user_ytd_amounts,
    calculate_service_period,
    calculate_leave_accrual,
    get_leave_summary,
    get_user_leave_summary,
    map_user_leave_data
)

from .database_utils import (
    get_db,
    close_db,
    get_company_config,
    get_venue_details,
    get_user_details,
    get_workplace_config
)

# ------------------------------#
#    Error Handling Utilities   #
# ------------------------------#    
from .error_utils import (
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
    api_route_with_error_handling
)

# -------------------------#
#    Logging Utilities     #
# -------------------------#    
from .logging import (
    AuditLogger,
    CustomJSONFormatter,
    setup_logging,
    log_event,
    log_api_request,
    log_security_event,
    cleanup_logs,
    get_log_stats
)

# ----------------------------------#
#   Request Processing Utilities    #
# ----------------------------------#    
from .request_utils import (
    get_request_data,
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
    validate_request_size
)

# -----------------------------------#
#    Session Management Utilities    #
# -----------------------------------#    
from .auth.session_utils import (  # FIXED: Changed from .session_utils to .auth.session_utils
    create_session,
    get_session,
    delete_session,
    refresh_session,
    validate_session,
    get_user_from_session,
    set_user_in_session
)

# ---------------------------------------#
#       User Management Utilities        #
# ---------------------------------------#    
from .user_utils import (
    create_user,
    get_user_by_id,
    update_user,
    delete_user,
    get_all_users,
    validate_user_data,
    authenticate_user,
    get_user_roles,
    assign_role_to_user,
    remove_role_from_user
)

# ---------------------------------------#
#         Notification Utilities         #
# ---------------------------------------#    
from .notification_utils import (
    send_email_notification,
    send_sms_notification,
    create_notification,
    get_notifications_for_user,
    mark_notification_as_read,
    delete_notification
)

# ---------------------------------------#
#         File Management Utilities      #
# ---------------------------------------#    
from .file_utils import (
    upload_file,
    delete_file,
    get_file_url,
    validate_file_type,
    resize_image,
    generate_file_name
)

# ---------------------------------------#
#         Caching Utilities              #
# ---------------------------------------#    
from .redis_utils import (
    set_cache,
    get_cache,
    delete_cache,
    clear_cache,
    cache_key_generator,
    get_hash,
    set_hash
)

# ---------------------------------------#
#         Analytics Utilities            #
# ---------------------------------------#    
#from .analytics_utils import (
#    track_event,
#    log_user_activity,
#    generate_report,
#    get_user_engagement_data,
#    analyze_trends
#)

# ---------------------------------------#
#         Payment Processing Utilities   #
# ---------------------------------------#    
# from .payment_utils import (
#    process_payment,
#    refund_payment,
#    validate_payment_info,
#    get_payment_status,
#    create_payment_intent
# )

# ---------------------------------------#
#         API Integration Utilities      #
# ---------------------------------------#    
# from .api_utils import (
#    call_external_api,
#    handle_api_response,
#    authenticate_api_request,
#    log_api_usage,
#    validate_api_key
# )

# ---------------------------------------#
#         Configuration Utilities        #
# ---------------------------------------#    
# from .config_utils import (
#    load_config,
#    save_config,
#    validate_config,
#    get_config_value,
#    set_config_value
# )

# ---------------------------------------#
#         Miscellaneous Utilities        #
# ---------------------------------------#    
# from .misc_utils import (
#    generate_slug,
#    format_currency,
#    parse_json,
#    format_json,
#    get_current_timestamp
# )

__all__ = [
    # Authentication
    'validate_payroll_id',
    'hash_password',
    'check_password',
    'SessionManager',
    'SessionExpiredError',
    'AuthManager',
    'login_required',
    'require_permission',
    'admin_required',
    'api_key_required',
    
    # Allergen Management
    'lookup_allergen',
    'get_allergen_by_id',
    'create_allergen',
    'update_allergen',
    'delete_allergen',
    'search_allergens',
    'validate_allergen_data',
    'AllergenError',
    
    # Recipe and Search
    'lookup_ingredient',
    'lookup_tag',
    'lookup_cuisine',
    'lookup_method',
    'lookup_dietary',
    'lookup_mealtype',
    'lookup_recipeIngredient',
    'lookup_globalRecipe',
    
    # Time Management
    'timeago',
    'generate_timestamp',
    'format_datetime',
    'parse_datetime',
    
    # Note Management
    'create_user_note',
    'get_user_notes',
    'get_user_note_by_id',
    'update_user_note',
    'delete_user_note',
    
    # Business Management
    'lookup_business',
    'lookup_venue',
    'lookup_work_area',
    'create_business',
    'add_venue_to_business',
    'add_work_area_to_venue',
    'assign_user_to_business',
    'assign_user_to_work_area',
    'get_business_hierarchy',
    'update_business_status',
    'validate_business_structure',
    
    # Google Integration
    'validate_google_token',
    'get_google_service',
    'KeepService',
    
    # Defense
    # Security
    'generate_random_string',
    'generate_secure_token',
    'generate_id_with_prefix',
    'hash_string',
    'constant_time_compare',
    'generate_session_id',
    'sanitize_input',
    'log_security_event',
    # Rate Limiting
    'RateLimiter',
    # Validation
    'validate_request_data',
    'validate_id_format',
    'validate_uuid',
    'validate_email',
    'validate_date_format',
    'validate_phone_number',
    'validate_required_fields',
    'validate_field_length',
    'validate_numeric_range',
    'validate_business_data',
    'validate_venue_data',
    'validate_work_area_data',
    
    # Database
    'safe_object_id',
    'format_mongo_doc',
    'create_mongo_query',
    'handle_mongo_error',
    'sanitize_mongo_query',
    'build_aggregation_pipeline',
    'update_timestamp_fields',
    'get_collection_stats',
    'ensure_indexes',
    'bulk_write_operations',
    'get_distinct_values',
    'execute_transaction',
    'get_db',
    'close_db',
    'get_company_config',
    'get_venue_details',
    'get_user_details',
    'get_workplace_config',
    
    # Payroll
    'calculate_tax',
    'calculate_period_amounts',
    'calculate_ytd_amounts',
    'get_user_ytd_amounts',
    'calculate_service_period',
    'calculate_leave_accrual',
    'get_leave_summary',
    'get_user_leave_summary',
    'map_user_leave_data',
    
    # Error Handling
    'AppError',
    'ValidationError',
    'AuthenticationError',
    'PermissionError',
    'NotFoundError',
    'DatabaseError',
    'handle_error',
    'log_error',
    'format_error_response',
    'validate_or_raise',
    'assert_found',
    'assert_valid',
    'assert_permitted',
    'get_error_context',
    'api_route_with_error_handling',
    
    # Logging
    'AuditLogger',
    'CustomJSONFormatter',
    'setup_logging',
    'log_event',
    'log_api_request',
    'log_security_event',
    'cleanup_logs',
    'get_log_stats',
    
    # Request Processing
    'get_request_data',
    'format_response',
    'paginate_results',
    'parse_query_params',
    'validate_content_type',
    'rate_limit',
    'log_request_info',
    'get_client_ip',
    'get_pagination_params',
    'get_sort_params',
    'get_filter_params',
    'validate_request_size',
    
    # Session Management
    'create_session',
    'get_session',
    'delete_session',
    'refresh_session',
    'validate_session',
    'get_user_from_session',
    'set_user_in_session',
    
    # User Management
    'create_user',
    'get_user_by_id',
    'update_user',
    'delete_user',
    'get_all_users',
    'validate_user_data',
    'authenticate_user',
    'get_user_roles',
    'assign_role_to_user',
    'remove_role_from_user',
    
    # Notification
    'send_email_notification',
    'send_sms_notification',
    'create_notification',
    'get_notifications_for_user',
    'mark_notification_as_read',
    'delete_notification',
    
    # File Management
    'upload_file',
    'delete_file',
    'get_file_url',
    'validate_file_type',
    'resize_image',
    'generate_file_name',
    
    # Caching
    'set_cache',
    'get_cache',
    'delete_cache',
    'clear_cache',
    'cache_key_generator',
    
    # Analytics
    'track_event',
    'log_user_activity',
    'generate_report',
    'get_user_engagement_data',
    'analyze_trends',
    
    # Payment Processing
    'process_payment',
    'refund_payment',
    'validate_payment_info',
    'get_payment_status',
    'create_payment_intent',
    
    # API Integration
    'call_external_api',
    'handle_api_response',
    'authenticate_api_request',
    'log_api_usage',
    'validate_api_key',
    
    # Configuration
    'load_config',
    'save_config',
    'validate_config',
    'get_config_value',
    'set_config_value',
    
    # Miscellaneous
    'generate_slug',
    'format_currency',
    'parse_json',
    'format_json',
    'get_current_timestamp'
]
