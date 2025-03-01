"""
Analytics utilities for tracking user events and generating reports.
Provides functions for tracking application usage and analyzing trends.
"""
import json
import logging
from datetime import datetime
from flask import current_app, request, g
from bson.objectid import ObjectId

logger = logging.getLogger(__name__)

def get_analytics_db():
    """
    Get the MongoDB collection for analytics data.
    
    Returns:
        MongoDB collection or None if not configured
    """
    if hasattr(current_app, 'mongo') and hasattr(current_app.mongo, 'db'):
        return current_app.mongo.db.analytics
    return None

def track_event(event_type, data=None, user_id=None):
    """
    Track a user or system event in the analytics database.
    
    Args:
        event_type (str): Type of event (e.g., 'page_view', 'login', 'search')
        data (dict, optional): Additional event data. Defaults to None.
        user_id (str, optional): User ID associated with the event. Defaults to None.
        
    Returns:
        str: Event ID if successful, None otherwise
    """
    analytics_db = get_analytics_db()
    if not analytics_db:
        logger.debug("Analytics database not configured, skipping event tracking")
        return None
    
    try:
        # Get current timestamp
        timestamp = datetime.utcnow()
        
        # Get request info if available
        ip_address = None
        user_agent = None
        path = None
        
        if request:
            ip_address = request.remote_addr
            user_agent = request.user_agent.string if hasattr(request, 'user_agent') else None
            path = request.path
        
        # Get user from session if not provided
        if user_id is None and hasattr(g, 'user') and hasattr(g.user, 'id'):
            user_id = g.user.id
        
        # Prepare event document
        event = {
            'event_type': event_type,
            'timestamp': timestamp,
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'path': path,
            'data': data or {}
        }
        
        # Insert event
        result = analytics_db.insert_one(event)
        
        if result and result.inserted_id:
            logger.debug(f"Event tracked: {event_type}, ID: {result.inserted_id}")
            return str(result.inserted_id)
        
        return None
    except Exception as e:
        logger.error(f"Error tracking event: {str(e)}")
        return None

def log_user_activity(user_id, activity_type, details=None):
    """
    Log user activity for analytics purposes.
    
    Args:
        user_id (str): User ID
        activity_type (str): Type of activity (e.g., 'content_creation', 'profile_update')
        details (dict, optional): Additional activity details. Defaults to None.
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        return track_event(
            event_type=f"user_activity_{activity_type}",
            data={
                'activity_type': activity_type,
                'details': details or {}
            },
            user_id=user_id
        ) is not None
    except Exception as e:
        logger.error(f"Error logging user activity: {str(e)}")
        return False

def generate_report(report_type, params=None):
    """
    Generate an analytics report.
    
    Args:
        report_type (str): Type of report to generate
        params (dict, optional): Report parameters. Defaults to None.
        
    Returns:
        dict: Report data or None if generation failed
    """
    analytics_db = get_analytics_db()
    if not analytics_db:
        logger.debug("Analytics database not configured, skipping report generation")
        return None
    
    try:
        params = params or {}
        report_data = None
        
        # Process different report types
        if report_type == 'user_activity':
            # User activity report
            pipeline = [
                {'$match': {'user_id': {'$exists': True, '$ne': None}}},
                {'$group': {
                    '_id': '$user_id',
                    'activity_count': {'$sum': 1},
                    'last_activity': {'$max': '$timestamp'}
                }},
                {'$sort': {'last_activity': -1}}
            ]
            
            # Apply date filters if provided
            if 'start_date' in params:
                start_date = params['start_date']
                pipeline[0]['$match']['timestamp'] = {'$gte': start_date}
            
            if 'end_date' in params:
                end_date = params['end_date']
                if 'timestamp' in pipeline[0]['$match']:
                    pipeline[0]['$match']['timestamp']['$lte'] = end_date
                else:
                    pipeline[0]['$match']['timestamp'] = {'$lte': end_date}
            
            # Execute aggregation
            report_data = list(analytics_db.aggregate(pipeline))
            
        elif report_type == 'page_views':
            # Page views report
            pipeline = [
                {'$match': {'event_type': 'page_view'}},
                {'$group': {
                    '_id': '$path',
                    'view_count': {'$sum': 1},
                    'unique_users': {'$addToSet': '$user_id'}
                }},
                {'$project': {
                    'path': '$_id',
                    'view_count': 1,
                    'unique_user_count': {'$size': '$unique_users'}
                }},
                {'$sort': {'view_count': -1}}
            ]
            
            # Execute aggregation
            report_data = list(analytics_db.aggregate(pipeline))
            
        elif report_type == 'event_summary':
            # Event summary report
            pipeline = [
                {'$group': {
                    '_id': '$event_type',
                    'count': {'$sum': 1},
                    'first_seen': {'$min': '$timestamp'},
                    'last_seen': {'$max': '$timestamp'}
                }},
                {'$sort': {'count': -1}}
            ]
            
            # Execute aggregation
            report_data = list(analytics_db.aggregate(pipeline))
        
        # Format and return report
        return {
            'report_type': report_type,
            'generated_at': datetime.utcnow(),
            'params': params,
            'data': report_data
        }
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return None

def get_user_engagement_data(user_id, start_date=None, end_date=None):
    """
    Get engagement data for a specific user.
    
    Args:
        user_id (str): User ID
        start_date (datetime, optional): Start date for filtering. Defaults to None.
        end_date (datetime, optional): End date for filtering. Defaults to None.
        
    Returns:
        dict: User engagement data or None if retrieval failed
    """
    analytics_db = get_analytics_db()
    if not analytics_db:
        logger.debug("Analytics database not configured, skipping user engagement data retrieval")
        return None
    
    try:
        # Prepare match criteria
        match = {'user_id': user_id}
        
        if start_date or end_date:
            match['timestamp'] = {}
            
            if start_date:
                match['timestamp']['$gte'] = start_date
                
            if end_date:
                match['timestamp']['$lte'] = end_date
        
        # Aggregate user engagement data
        pipeline = [
            {'$match': match},
            {'$group': {
                '_id': '$event_type',
                'count': {'$sum': 1},
                'first_activity': {'$min': '$timestamp'},
                'last_activity': {'$max': '$timestamp'}
            }},
            {'$sort': {'count': -1}}
        ]
        
        # Execute aggregation
        event_stats = list(analytics_db.aggregate(pipeline))
        
        # Calculate overall stats
        total_events = sum(stat['count'] for stat in event_stats)
        
        # Format and return data
        return {
            'user_id': user_id,
            'total_events': total_events,
            'start_date': start_date,
            'end_date': end_date,
            'event_breakdown': event_stats
        }
    except Exception as e:
        logger.error(f"Error retrieving user engagement data: {str(e)}")
        return None

def analyze_trends(event_type=None, time_period='daily', start_date=None, end_date=None):
    """
    Analyze trends in analytics data.
    
    Args:
        event_type (str, optional): Filter by event type. Defaults to None (all events).
        time_period (str, optional): Time period for grouping ('hourly', 'daily', 'weekly', 'monthly'). Defaults to 'daily'.
        start_date (datetime, optional): Start date for analysis. Defaults to None.
        end_date (datetime, optional): End date for analysis. Defaults to None.
        
    Returns:
        dict: Trend analysis data or None if analysis failed
    """
    analytics_db = get_analytics_db()
    if not analytics_db:
        logger.debug("Analytics database not configured, skipping trend analysis")
        return None
    
    try:
        # Prepare match criteria
        match = {}
        
        if event_type:
            match['event_type'] = event_type
        
        if start_date or end_date:
            match['timestamp'] = {}
            
            if start_date:
                match['timestamp']['$gte'] = start_date
                
            if end_date:
                match['timestamp']['$lte'] = end_date
        
        # Define date grouping based on time period
        date_format = '%Y-%m-%d'
        date_parts = {'year': '%Y', 'month': '%m', 'day': '%d'}
        
        if time_period == 'hourly':
            date_format = '%Y-%m-%d %H:00'
            date_parts['hour'] = '%H'
        elif time_period == 'weekly':
            date_format = '%Y-W%U'
            date_parts = {'year': '%Y', 'week': '%U'}
        elif time_period == 'monthly':
            date_format = '%Y-%m'
            date_parts = {'year': '%Y', 'month': '%m'}
        
        # Create pipeline for trend analysis
        pipeline = [
            {'$match': match},
            {'$group': {
                '_id': {
                    # Group by date parts based on time period
                    **{k: {'$dateToString': {'format': v, 'date': '$timestamp'}} for k, v in date_parts.items()},
                    'event_type': '$event_type'
                },
                'count': {'$sum': 1},
                'unique_users': {'$addToSet': '$user_id'}
            }},
            {'$project': {
                'date_key': {
                    '$dateToString': {
                        'format': date_format,
                        'date': '$timestamp'
                    } if 'timestamp' in '$_id' else {
                        # Handle different time period formats
                        '$concat': [
                            '$_id.year',
                            time_period == 'monthly' ? '-' : '-W',
                            time_period == 'monthly' ? '$_id.month' : '$_id.week'
                        ] if time_period in ['weekly', 'monthly'] else {
                            '$concat': [
                                '$_id.year', '-', '$_id.month', '-', '$_id.day',
                                time_period == 'hourly' ? ' ' : '',
                                time_period == 'hourly' ? '$_id.hour' : '',
                                time_period == 'hourly' ? ':00' : ''
                            ]
                        }
                    }
                },
                'event_type': '$_id.event_type',
                'count': 1,
                'unique_user_count': {'$size': '$unique_users'}
            }},
            {'$sort': {'date_key': 1, 'event_type': 1}}
        ]
        
        # Execute aggregation
        trend_data = list(analytics_db.aggregate(pipeline))
        
        # Format results
        formatted_data = []
        for item in trend_data:
            formatted_data.append({
                'date': item['date_key'],
                'event_type': item['event_type'],
                'count': item['count'],
                'unique_users': item['unique_user_count']
            })
        
        # Return trend analysis
        return {
            'time_period': time_period,
            'event_type': event_type or 'all',
            'start_date': start_date,
            'end_date': end_date,
            'trends': formatted_data
        }
    except Exception as e:
        logger.error(f"Error analyzing trends: {str(e)}")
        return None
