""" shsmd
"""

import sqlite3
from flask import g
from shsmd.config import CONF
from shsmd import app

def get_db():
    """ Connect to sqlite database.

        Queries against db connection will be returned as
        dict rather than list.

        Returns:
            sqlite3.Connection: database connection object
    """

    database = getattr(g, '_database', None)
    if database is None:
        database = g._database = sqlite3.connect(CONF.database)
        database.row_factory = sqlite3.Row
    return database

@app.teardown_appcontext
def close_connection(exception):
    """ Close database connection object.
    """

    database = getattr(g, '_database', None)
    if database is not None:
        database.close()

def query_db(query, args=(), one=False):
    """ Execute a SQL query and fetch results.

        Args:
            query   (str): SQL querystring.
            args  (tuple): SQL query arguments.
            one (boolean): Return a singleton row if True, list if False.

        Returns:
            Result of SQL querystring.
    """

    cur = get_db().execute(query, args)
    results = cur.fetchall()
    cur.close()
    return (results[0] if results else None) if one else results

def init_db():
    """ Initialise the database using provided schema.
    """

    with app.app_context():
        database = get_db()
        with app.open_resource(CONF.schema, mode='r') as db_file:
            database.cursor().executescript(db_file.read())
        database.commit()
