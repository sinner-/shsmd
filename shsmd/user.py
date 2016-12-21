""" shsmd
"""

from flask_restful import Resource
from flask_restful import reqparse
from flask_restful import abort
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from shsmd.db import query_db
from shsmd.db import get_db

class User(Resource):
    """ flask restful class for users.

        Currentl only handles user registration via HTTP POST.
    """

    def post(self):
        """ user registration method.

            Args:
                username          (str): Desired username to register with shsmd.
                master_verify_key (str): NaCl verification key for adding new devices.

            Returns:
                HTTP 422: If the desired username is already registered.

                HTTP 400: If the provided master_verify_key is not a valid NaCl verify
                key.

                username, HTTP 201: If the user registration was successful.

        """

        parser = reqparse.RequestParser()
        parser.add_argument('username',
                            type=str,
                            required=True,
                            help="username is either blank or incorrect type.")
        parser.add_argument('master_verify_key',
                            type=str,
                            required=True,
                            help="master_verify_key is either blank or incorrect type.")
        args = parser.parse_args()

        #check if user exists already
        username = query_db('''
                            SELECT username
                            FROM users
                            WHERE username=%s;''',
                            (args['username'],),
                            one=True)
        if username is not None:
            abort(422, message="username already registered.")

        #check if provided key is a valid key
        try:
            VerifyKey(args['master_verify_key'], encoder=HexEncoder)
        except TypeError:
            abort(400,
                  message="The provided master_verify_key is not valid.")

        #otherwise, add user
        query_db('''
                 INSERT INTO users
                 VALUES(%s, %s);''',
                 (args['username'],
                  args['master_verify_key']))
        get_db().commit()

        return args['username'], 201
