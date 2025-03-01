# ------------------------------------------------------------
# models/role_model.py
# ------------------------------------------------------------


from datetime import datetime
from pymongo import ReturnDocument
from config import Config

"""
This module manages Role documents in the MongoDB
collection defined by Config.COLLECTION_BUSINESS_ROLES.
Each Role doc looks like this:

{
  "role_name": "senior_management",
  "permissions": [
    {
      "permissionName": "editFinancialReports",
      "global": True,
      "requiresHrApproval": False,
      "requiresSecondaryApproval": True,
      "requiresCoSign": False,
      "requestPermission": False,
      "venueOverrides": {
        "VENUE123": { "value": False, "requiresCoSign": True },
        ...
      }
    },
    ...
  ],
  "created_at": <datetime>,
  "updated_at": <datetime>
}
"""

def get_roles_collection(db):
    """Return the 'business_roles' collection."""
    return db[Config.COLLECTION_BUSINESS_ROLES]

def create_role(db, role_data):
    """
    Insert a new role document.
    role_data must contain at least:
      - 'role_name': str
      - 'permissions': list of permission objects
    """
    roles_coll = get_roles_collection(db)
    role_data["created_at"] = datetime.utcnow()
    role_data["updated_at"] = datetime.utcnow()

    result = roles_coll.insert_one(role_data)
    return roles_coll.find_one({"_id": result.inserted_id})

def find_role_by_name(db, role_name):
    """Find a role by 'role_name'."""
    roles_coll = get_roles_collection(db)
    return roles_coll.find_one({"role_name": role_name})

def update_role(db, role_name, update_fields):
    """
    Update an existing role doc.
    update_fields might be {"permissions": [...]} or others.
    """
    roles_coll = get_roles_collection(db)
    update_fields["updated_at"] = datetime.utcnow()

    return roles_coll.find_one_and_update(
        {"role_name": role_name},
        {"$set": update_fields},
        return_document=ReturnDocument.AFTER
    )

def delete_role(db, role_name):
    """Delete a role by 'role_name'."""
    roles_coll = get_roles_collection(db)
    result = roles_coll.delete_one({"role_name": role_name})
    return result.deleted_count > 0

def find_all_roles(db):
    """Return all role docs."""
    roles_coll = get_roles_collection(db)
    return list(roles_coll.find())
