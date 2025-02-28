# ------------------------------------------------------------
# utils/notes_utils.py
# ------------------------------------------------------------
from datetime import datetime
import uuid
import logging

logger = logging.getLogger(__name__)

def create_user_note(db, title, items=None, labels=None):
    """
    Create a new user note in the 'notes' (or 'user_notes') collection.
    Returns the newly inserted note document.
    """
    if items is None:
        items = []
    if labels is None:
        labels = []

    data = {
        "id": str(uuid.uuid4()),
        "title": title,
        "items": items,
        "labels": labels,
        "created_at": datetime.utcnow()
    }

    db.notes.insert_one(data)  # or db.user_notes if that's your collection name
    return data

def get_user_notes(db, search=None):
    """
    Retrieve all user notes. Optionally, search by partial match on 'title' or 'labels'.
    Returns a list of note documents.
    """
    query = {}
    if search:
        query = {
            "$or": [
                {"title": {"$regex": search, "$options": "i"}},
                {"labels": {"$regex": search, "$options": "i"}}
            ]
        }
    notes_cursor = db.notes.find(query, {"_id": 0})
    notes_list = list(notes_cursor)
    return notes_list

def get_user_note_by_id(db, note_id):
    """
    Retrieve a specific note by its 'id' field.
    Returns the note document, or None if not found.
    """
    note = db.notes.find_one({"id": note_id}, {"_id": 0})
    return note

def update_user_note(db, note_id, fields):
    """
    Update an existing note's fields.
    'fields' is a dict of {fieldname: new_value}.
    Returns the updated note or None if not found.
    """
    result = db.notes.find_one_and_update(
        {"id": note_id},
        {"$set": fields},
        return_document=True
    )
    return result

def delete_user_note(db, note_id):
    """
    Delete a note by 'id'.
    Returns True if deleted, False if no match found.
    """
    result = db.notes.delete_one({"id": note_id})
    return result.deleted_count > 0

def validate_note_data(title, items=None, labels=None):
    """
    Validate note data before creation or update.
    Returns (is_valid, error_message).
    """
    if not title or not isinstance(title, str):
        return False, "Title is required and must be a string"
    
    if items is not None and not isinstance(items, list):
        return False, "Items must be a list"
        
    if labels is not None and not isinstance(labels, list):
        return False, "Labels must be a list"
        
    return True, None

def search_notes_by_label(db, label):
    """
    Search notes by label.
    Returns a list of notes containing the specified label.
    """
    return list(db.notes.find(
        {"labels": {"$regex": f"^{label}$", "$options": "i"}},
        {"_id": 0}
    ))

def get_note_labels(db):
    """
    Get all unique labels used in notes.
    Returns a list of unique labels.
    """
    return db.notes.distinct("labels")

def archive_note(db, note_id):
    """
    Archive a note instead of deleting it.
    Returns the archived note or None if not found.
    """
    return db.notes.find_one_and_update(
        {"id": note_id},
        {
            "$set": {
                "archived": True,
                "archived_at": datetime.utcnow()
            }
        },
        return_document=True
    )

def restore_note(db, note_id):
    """
    Restore an archived note.
    Returns the restored note or None if not found.
    """
    return db.notes.find_one_and_update(
        {"id": note_id},
        {
            "$set": {
                "archived": False
            },
            "$unset": {
                "archived_at": ""
            }
        },
        return_document=True
    )
