# ------------------------------------------------------------
#----        routes/auth/permission_manager.py      -------
# ------------------------------------------------------------
from flask import Blueprint, request, jsonify, current_app, g, session
from pymongo import MongoClient
from config import Config
from datetime import datetime
from functools import wraps

# Import helper functions from our models
from models.role_model import find_all_roles, find_role_by_name, update_role
from models.user_model import assign_role_to_user, find_user_in_business, update_user_override

permission_manager = Blueprint('permission_manager', __name__, url_prefix='/permissions')

def get_effective_permissions(role_permissions, user_overrides, venue_id=None):
    """
    Merges the base role permissions with user-specific overrides and venue-specific overrides.
    Each permission object should have:
        - "permissionName" (the name of the permission)
        - "global" (True/False)
        - Optional flags: "requiresHrApproval", "requiresSecondaryApproval", "requiresCoSign", "requestPermission"
        - Optional "venueOverrides": a dict mapping venue IDs to overrides.
    If user_overrides is provided (a dict where keys are permissionName), then those values override the role.
    """
    effective = {}

    for perm in role_permissions:
        name = perm.get("permissionName")
        # Start with the base global value and flags
        effective[name] = {
            "value": perm.get("global", False),
            "requiresHrApproval": perm.get("requiresHrApproval", False),
            "requiresSecondaryApproval": perm.get("requiresSecondaryApproval", False),
            "requiresCoSign": perm.get("requiresCoSign", False),
            "requestPermission": perm.get("requestPermission", False),
        }
        # If venue_id is specified and an override exists, apply it.
        venue_overrides = perm.get("venueOverrides", {})
        if venue_id and venue_overrides and isinstance(venue_overrides, dict):
            if venue_id in venue_overrides:
                v_override = venue_overrides[venue_id]
                effective[name]["value"] = v_override.get("value", effective[name]["value"])
                effective[name]["requiresHrApproval"] = v_override.get("requiresHrApproval", effective[name]["requiresHrApproval"])
                effective[name]["requiresSecondaryApproval"] = v_override.get("requiresSecondaryApproval", effective[name]["requiresSecondaryApproval"])
                effective[name]["requiresCoSign"] = v_override.get("requiresCoSign", effective[name]["requiresCoSign"])
                effective[name]["requestPermission"] = v_override.get("requestPermission", effective[name]["requestPermission"])
    
    # Apply user overrides, which have final priority.
    if user_overrides and isinstance(user_overrides, dict):
        for perm_name, override in user_overrides.items():
            if perm_name in effective:
                effective[perm_name]["value"] = override.get("value", effective[perm_name]["value"])
                effective[perm_name]["requiresHrApproval"] = override.get("requiresHrApproval", effective[perm_name]["requiresHrApproval"])
                effective[perm_name]["requiresSecondaryApproval"] = override.get("requiresSecondaryApproval", effective[perm_name]["requiresSecondaryApproval"])
                effective[perm_name]["requiresCoSign"] = override.get("requiresCoSign", effective[perm_name]["requiresCoSign"])
                effective[perm_name]["requestPermission"] = override.get("requestPermission", effective[perm_name]["requestPermission"])
            else:
                effective[perm_name] = override

    return effective

def require_permission(permission_name, venue_id=None):
    """
    Decorator to enforce that the current user has the required permission.
    It assumes that user information is available in g.user or the session.
    
    Usage:
    
        @require_permission("editFinancialReports", venue_id="VENUE123")
        def some_route():
            ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Retrieve user data from g or session
            user = getattr(g, "user", None) or session.get("user")
            if not user:
                return jsonify({"success": False, "error": "User not authenticated"}), 401

            payroll_id = user.get("payroll_id")
            business_id = user.get("business_id")
            if not (payroll_id and business_id):
                return jsonify({"success": False, "error": "Incomplete user context"}), 401

            db = current_app.config['MONGO_CLIENT'][Config.MONGO_DBNAME]
            # Retrieve the user assignment from business_users collection
            user_doc = find_user_in_business(db, payroll_id, business_id)
            if not user_doc:
                return jsonify({"success": False, "error": "User not assigned to business"}), 403

            # Retrieve role information
            role_doc = find_role_by_name(db, user_doc.get("role_name"))
            if not role_doc:
                return jsonify({"success": False, "error": "Role not found"}), 403

            base_permissions = role_doc.get("permissions", [])
            user_overrides_field = user_doc.get("overrides", {})
            effective = get_effective_permissions(base_permissions, user_overrides_field, venue_id=venue_id)
            if not effective.get(permission_name, {}).get("value", False):
                return jsonify({"success": False, "error": "Permission denied"}), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator

def get_business_context():
    """
    A helper function to return current business context.
    Modify this function as needed to extract business/venue identifiers.
    """
    return {
        "business_id": g.get("business_id"),
        "venue_id": g.get("venue_id"),
        "timestamp": datetime.utcnow().isoformat()
    }

### API ENDPOINTS ###

@permission_manager.route('/', methods=['GET'])
def list_roles():
    """
    Lists all roles in the system.
    """
    try:
        db = current_app.config['MONGO_CLIENT'][Config.MONGO_DBNAME]
        roles = find_all_roles(db)
        roles_list = [{
            "role_name": role["role_name"],
            "permissions": role.get("permissions", []),
            "created_at": role.get("created_at"),
            "updated_at": role.get("updated_at")
        } for role in roles]
        return jsonify({"success": True, "roles": roles_list}), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@permission_manager.route('/assign', methods=['POST'])
def assign_role():
    """
    Assign a role to a user.
    Expected JSON payload:
    {
      "payroll_id": "<payroll_id>",
      "business_id": "<business_id>",
      "role_name": "<role_name>",
      "overrides": {    // (optional) user-specific override dictionary for permissions
          "permissionName1": {"value": false, "requiresCoSign": true},
          ...
      }
    }
    """
    try:
        data = request.get_json()
        payroll_id = data.get("payroll_id")
        business_id = data.get("business_id")
        role_name = data.get("role_name")
        overrides = data.get("overrides", {})

        if not (payroll_id and business_id and role_name):
            return jsonify({"success": False, "error": "Missing required fields"}), 400

        success = assign_role_to_user(
            current_app.config['MONGO_CLIENT'][Config.MONGO_DBNAME],
            payroll_id,
            business_id,
            role_name,
            override_data=overrides
        )
        if success:
            return jsonify({"success": True, "message": f"Role {role_name} assigned to user {payroll_id}"}), 200
        else:
            return jsonify({"success": False, "error": "Assignment failed"}), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@permission_manager.route('/check', methods=['POST'])
def check_permission():
    """
    Check if a user has a specific permission effective for a given venue.
    Expected JSON payload:
    {
       "payroll_id": "<payroll_id>",
       "business_id": "<business_id>",
       "permission_name": "<permissionName>",
       "venue_id": "<venue_id>"   // (Optional) for venue-specific override.
    }
    """
    try:
        data = request.get_json()
        payroll_id = data.get("payroll_id")
        business_id = data.get("business_id")
        permission_name = data.get("permission_name")
        venue_id = data.get("venue_id")

        if not (payroll_id and business_id and permission_name):
            return jsonify({"success": False, "error": "Missing required fields"}), 400

        db = current_app.config['MONGO_CLIENT'][Config.MONGO_DBNAME]
        user_doc = find_user_in_business(db, payroll_id, business_id)
        if not user_doc:
            return jsonify({"success": False, "error": "User not assigned to business"}), 404

        role_doc = find_role_by_name(db, user_doc.get("role_name"))
        if not role_doc:
            return jsonify({"success": False, "error": "Role not found"}), 404

        base_permissions = role_doc.get("permissions", [])
        user_overrides_field = user_doc.get("overrides", {})

        effective = get_effective_permissions(base_permissions, user_overrides_field, venue_id=venue_id)
        has_permission = effective.get(permission_name, {}).get("value", False)

        return jsonify({
            "success": True,
            "permission": permission_name,
            "effective": effective.get(permission_name, {}),
            "allowed": has_permission
        }), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@permission_manager.route('/roles/<role_name>', methods=['PUT'])
def update_role_permissions(role_name):
    """
    Update permissions for a given role.
    Expected JSON payload:
    {
         "permissions": [ <list of updated permission objects> ]
    }
    """
    try:
        data = request.get_json()
        updated_permissions = data.get("permissions")
        if updated_permissions is None:
            return jsonify({"success": False, "error": "Missing 'permissions' in request body"}), 400

        db = current_app.config['MONGO_CLIENT'][Config.MONGO_DBNAME]
        updated_role = update_role(db, role_name, {"permissions": updated_permissions})
        if updated_role:
            return jsonify({"success": True, "updated_role": updated_role}), 200
        else:
            return jsonify({"success": False, "error": "Role update failed"}), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Export the public objects for other modules to import
__all__ = [
    "permission_manager",
    "get_effective_permissions",
    "require_permission",
    "get_business_context"
]

if __name__ == "__main__":
    # For local testing only
    from flask import Flask
    from pymongo import MongoClient
    app = Flask(__name__)
    app.config['MONGO_CLIENT'] = MongoClient(Config.MONGO_URI)
    app.register_blueprint(permission_manager)
    app.run(debug=True, port=5001)
