""" shsmd
"""

import pymysql
from flask import g
from shsmd.common.config import Configuration
from shsmd.api import app

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

def create_schema():
    """ Initialise the database.
    """

    tables = '''
        CREATE TABLE users (
            username VARCHAR(65) PRIMARY KEY NOT NULL,
            master_verify_key VARCHAR(65) NOT NULL);
        CREATE TABLE devices (
            device_verify_key VARCHAR(65) PRIMARY KEY NOT NULL,
            username VARCHAR(65) NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username));
        CREATE TABLE pubkeys (
            device_public_key VARCHAR(173) PRIMARY KEY NOT NULL,
            device_verify_key VARCHAR(65) NOT NULL,
            FOREIGN KEY(device_verify_key) REFERENCES devices(device_verify_key));
        CREATE TABLE messages (
            message_id VARCHAR(65) PRIMARY KEY NOT NULL,
            reply_to VARCHAR(65) NOT NULL,
            message_contents LONGTEXT NOT NULL,
            message_public_key VARCHAR(173) NOT NULL,
            FOREIGN KEY (reply_to) REFERENCES users(username));
        CREATE TABLE message_recipients (
            device_verify_key VARCHAR(65) NOT NULL,
            message_id VARCHAR(65) NOT NULL,
            FOREIGN KEY(message_id) REFERENCES messages(message_id));
        CREATE INDEX users_username ON users (username);
        CREATE INDEX devices_username ON devices (username);
        CREATE INDEX devices_verify_key ON devices (device_verify_key);
        CREATE INDEX recipients_verify_key ON message_recipients (device_verify_key);
        CREATE INDEX messages_message_id ON messages (message_id);
    '''

    with app.app_context():
        query_db(tables)

def drop_schema():
    """ Clear all data.
    """

    tables = '''
        DROP INDEX IF EXISTS messages_message_id ON messages;
        DROP INDEX IF EXISTS recipients_verify_key ON message_recipients;
        DROP INDEX IF EXISTS devices_verify_key ON devices;
        DROP INDEX IF EXISTS devices_username ON devices;
        DROP INDEX IF EXISTS users_username ON users;
        DROP TABLE IF EXISTS message_recipients;
        DROP TABLE IF EXISTS messages;
        DROP TABLE IF EXISTS pubkeys;
        DROP TABLE IF EXISTS devices;
        DROP TABLE IF EXISTS users;
    '''

    with app.app_context():
        query_db(tables)
