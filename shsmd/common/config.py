""" shsmd
"""

import ConfigParser

class Configuration(object):
    """ Configuration class for shsmd.

        Attributes:
            database  (str): Path to sqlite database.
            debug (boolean): Toggle to enable debug.
    """

    def __init__(self):
        """ Configuration class initialisation.

        """

        config = ConfigParser.RawConfigParser()
        config.read('config.ini')

        self.debug = config.getboolean('general', 'debug')
        self.mysql_hostname = config.get('database', 'mysql_hostname')
        self.mysql_port = int(config.get('database', 'mysql_port'))
        self.mysql_username = config.get('database', 'mysql_username')
        self.mysql_password = config.get('database', 'mysql_password')
        self.mysql_database = config.get('database', 'mysql_database')

    def get(self):
        """ Return configuration object.
        """

        return self

    def set(self):
        """ Mutator method, currently does nothing.
        """
        pass
