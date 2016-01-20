''' xx '''
import sqlite3
from flask import g
from shsmd.config import CONF
from shsmd import app

def get_db():
    ''' xxx '''
    database = getattr(g, '_database', None)
    if database is None:
        database = g._database = sqlite3.connect(CONF.database)
        database.row_factory = sqlite3.Row
    return database

@app.teardown_appcontext
def close_connection(exception):
    ''' xxx '''
    database = getattr(g, '_database', None)
    if database is not None:
        database.close()

def query_db(query, args=(), one=False):
    ''' xxx '''
    cur = get_db().execute(query, args)
    results = cur.fetchall()
    cur.close()
    return (results[0] if results else None) if one else results

def init_db():
    ''' xxx '''
    with app.app_context():
        database = get_db()
        with app.open_resource(CONF.schema, mode='r') as db_file:
            database.cursor().executescript(db_file.read())
        database.commit()
