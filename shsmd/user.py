''' x '''
from flask_restful import Resource
from flask_restful import reqparse
from flask_restful import abort
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from shsmd.db import query_db
from shsmd.db import get_db

class User(Resource):
    ''' x '''
    def post(self):
        ''' x '''
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str)
        parser.add_argument('master_verify_key', type=str)
        args = parser.parse_args()

        #check if user exists already
        username = query_db('''
                            SELECT username
                            FROM users
                            WHERE username = ?;''',
                            [args['username']],
                            one=True)
        if username is not None:
            abort(422, message="username already registered.")

        #check if provided key is a valid key
        try:
            master_verify_key = VerifyKey(
                args['master_verify_key'],
                encoder=HexEncoder)
        except TypeError:
            abort(400,
                  message="The provided master_verify_key is not valid.")

        #otherwise, add user
        query_db('''
                 INSERT INTO users
                 VALUES(?, ?);''',
                 [args['username'],
                  args['master_verify_key']])
        get_db().commit()

        return args['username'], 201
