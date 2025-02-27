"""
Utility functions for database operations with MongoDB.
"""
from pymongo import MongoClient
from flask import current_app, g
from bson.objectid import ObjectId
import os

def get_db():
    """
    Get the database connection from Flask's application context.
    Creates a new connection if none exists.
    
    Returns:
        pymongo.database.Database: MongoDB database connection
    """
    if 'db' not in g:
        mongo_uri = current_app.config.get('MONGO_URI', 'mongodb://localhost:27017/')
        client = MongoClient(mongo_uri)
        g.client = client
        g.db = client.get_database(current_app.config.get('MONGO_DBNAME', 'payroll_db'))
    return g.db

def close_db(e=None):
    """
    Close the database connection at the end of a request.
    
    Args:
        e: Optional exception that occurred during the request
    """
    client = g.pop('client', None)
    if client is not None:
        client.close()

def get_company_config(company_id):
    """
    Get company configuration from business_entities collection.
    
    Args:
        company_id (str): Company ID to retrieve configuration for
        
    Returns:
        dict: Company configuration details or None if not found
    """
    db = get_db()
    return db.business_entities.find_one({"company_id": company_id})

def get_venue_details(venue_id):
    """
    Get venue details from business_venues collection.
    
    Args:
        venue_id (str): Venue ID to retrieve details for
        
    Returns:
        dict: Venue details or None if not found
    """
    db = get_db()
    return db.business_venues.find_one({"venue_id": venue_id})

def get_user_details(linking_id=None, payroll_id=None):
    """
    Get user details from business_users collection.
    
    Args:
        linking_id (str, optional): User linking ID
        payroll_id (str, optional): User payroll ID
        
    Returns:
        dict: User details or None if not found
    """
    db = get_db()
    query = {}
    if linking_id:
        query["linking_id"] = linking_id
    elif payroll_id:
        query["payroll_id"] = payroll_id
    else:
        return None
    
    return db.business_users.find_one(query)

def get_workplace_config(user_data):
    """
    Get comprehensive workplace configuration based on user data.
    
    Args:
        user_data (dict): User details including company_id and venue_id
        
    Returns:
        dict: Comprehensive workplace configuration
    """
    if not user_data:
        return None
    
    company_id = user_data.get('company_id')
    venue_id = user_data.get('venue_id')
    
    # Get company configuration
    company_config = get_company_config(company_id) if company_id else None
    
    # Get venue details
    venue_details = get_venue_details(venue_id) if venue_id else None
    
    # Combine configuration
    config = {
        "user": {
            "linking_id": user_data.get('linking_id'),
            "payroll_id": user_data.get('payroll_id'),
            "first_name": user_data.get('first_name'),
            "last_name": user_data.get('last_name'),
            "preferred_name": user_data.get('preferred_name'),
            "role_name": user_data.get('role_name'),
            "work_area_name": user_data.get('work_area_name'),
            "work_area_id": user_data.get('work_area_id'),
        },
        "company": {
            "company_id": company_id,
            "company_name": company_config.get('company_name') if company_config else user_data.get('company_name'),
            "director_name": company_config.get('director_name') if company_config else None,
            "ACN": company_config.get('ACN') if company_config else None,
            "head_office": company_config.get('head_office') if company_config else None,
        },
        "venue": {
            "venue_id": venue_id,
            "venue_name": venue_details.get('venue_name') if venue_details else user_data.get('venue_name'),
            "venue_manager_name": venue_details.get('venue_manager_name') if venue_details else None,
            "address": venue_details.get('address') if venue_details else None,
            "suburb": venue_details.get('suburb') if venue_details else None,
            "state": venue_details.get('state') if venue_details else None,
            "post_code": venue_details.get('post_code') if venue_details else None,
            "phone": venue_details.get('phone') if venue_details else None,
            "email": venue_details.get('email') if venue_details else None,
        },
        "employment": user_data.get('employment_details', {}),
        "leave": user_data.get('leave_entitlements', {}),
        "accrued": user_data.get('accrued_employment', {})
    }
    
    return config
