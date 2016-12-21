#!bin/python
"""
Execution harness for Self Hosted Secure Messaging Daemon.

README.md contains instructions for installation and launch.

If debug mode is enabled (debug=True), all tables in the
database will be dropped and re-initialised on launch.

"""

from shsmd import app
from shsmd.db import init_db
from shsmd.config import CONF

def main():
    ''' starting harness function
        if debug is set it will wipe the database and start fresh.
    '''
    if CONF.debug:
        init_db()
    app.run(debug=CONF.debug)

if __name__ == '__main__':
    main()
