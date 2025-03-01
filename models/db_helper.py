# ------------------------------------------------------------
# models/db_helper.py
# ------------------------------------------------------------

from flask import g
from pymongo import MongoClient
from config import Config

def get_db(collection_name=None):
    """
    Return the database connection. If a collection name is provided, return that collection.
    """
    if 'db' not in g:
        client = MongoClient(Config.MONGO_URI)
        g.db = client[Config.MONGO_DBNAME]
    if collection_name:
        return g.db[collection_name]
    return g.db

def get_search_db():
    """
    Return the search database connection if used.
    """
    if 'search_db' not in g:
        client = MongoClient(Config.MONGO_URI)
        g.search_db = client[Config.MONGO_SEARCH_DBNAME]
    return g.search_db

def close_db(e=None):
    """
    Close the database connections after the request is finished.
    """
    db = g.pop('db', None)
    if db is not None:
        db.client.close()
    
    search_db = g.pop('search_db', None)
    if search_db is not None:
        search_db.client.close()

def register_teardown(app):
    """
    Register the teardown handler to close database connections.
    """
    @app.teardown_appcontext
    def teardown_db(exception):
        close_db()
