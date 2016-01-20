''' x '''
class Configuration(object):
    ''' x '''
    def __init__(self):
        ''' x '''
        self.database = "shsmd.db"
        self.debug = True
        self.schema = "../schema.sql"

    def get(self):
        ''' x '''
        return self

    def set(self):
        ''' x '''
        pass

CONF = Configuration().get()
