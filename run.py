#!bin/python
from shsmd import app
from shsmd.db import init_db
from shsmd.config import CONF

if __name__ == '__main__':
    if CONF.DEBUG:
        init_db()
    app.run(debug=CONF.DEBUG)
