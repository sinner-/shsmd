''' x '''
from flask import Flask
from flask_restful import Api

app = Flask(__name__)
app.config.from_object(__name__)
api = Api(app)

import shsmd.views
