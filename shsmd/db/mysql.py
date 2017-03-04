""" shsmd
"""

import pymysql
from flask import g
from shsmd.common.config import Configuration
from shsmd import app

def get_db():
    """ Connect to MySQL database.

        Queries against db connection will be returned as
        dict rather than list.

        Returns:
            pymysql.Connection: database connection object
    """

    config = Configuration().get()

    database = getattr(g, '_database', None)
    if database is None:
        g._database = pymysql.connect(host=config.mysql_hostname,
                                      port=config.mysql_port,
                                      user=config.mysql_username,
                                      passwd=config.mysql_password,
                                      db=config.mysql_database)
        database = g._database
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

    cur = get_db().cursor()
    cur.execute(query, args)
    results = cur.fetchall()
    cur.close()
    return (results[0] if results else None) if one else results

def init_db():
    """ Initialise the database using provided schema.
    """
    config = Configuration().get()

    with app.app_context():
        database = get_db()
        with app.open_resource(config.schema, mode='r') as db_file:
            database.cursor().execute(db_file.read())
        database.commit()
