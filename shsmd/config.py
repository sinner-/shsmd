""" shsmd
"""

import ConfigParser

class Configuration(object):
    """ Configuration class for shsmd.

        Attributes:
            database  (str): Path to sqlite database.
            debug (boolean): Toggle to enable debug.
            schema    (str): Path to sqlite schema.
    """

    def __init__(self):
        """ Configuration class initialisation.

        """

        config = ConfigParser.RawConfigParser()
        config.read('config.ini')

        self.debug = config.getboolean('general', 'debug')
        self.database = config.get('database', 'db_path')
        self.schema = config.get('database', 'schema_file')

    def get(self):
        """ Return configuration object.
        """

        return self

    def set(self):
        """ Mutator method, currently does nothing.
        """
        pass

CONF = Configuration().get()
