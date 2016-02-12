""" shsmd
"""

class Configuration(object):
    """ Configuration class for shsmd.

        Attributes:
            database  (str): Path to sqlite database.
            debug (boolean): Toggle to enable debug.
            schema    (str): Path to sqlite schema.
    """

    def __init__(self):
        """ Configuration class initialisation.

            Currently all values are hardcoded.
        """

        self.database = "shsmd.db"
        self.debug = True
        self.schema = "../schema.sql"

    def get(self):
        """ Return configuration object.
        """

        return self

    def set(self):
        """ Mutator method, currently does nothing.
        """
        pass

CONF = Configuration().get()
