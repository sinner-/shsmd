"""
Execution harness for Self Hosted Secure Messaging Daemon.

README.md contains instructions for installation and launch.

If debug mode is enabled (debug=True), all tables in the
database will be dropped and re-initialised on launch.

"""

from shsmd.api import app
from shsmd.common.config import Configuration

def main():
    ''' starting harness function
        if debug is set it will wipe the database and start fresh.
    '''

    config = Configuration().get()

    app.run(debug=config.debug)
