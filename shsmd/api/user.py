""" shsmd
"""

from flask_restful import Resource
from flask_restful import reqparse
from flask_restful import abort
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from shsmd.db.mysql import query_db
from shsmd.db.mysql import get_db


class User(Resource):
    """ flask restful class for registering a username.
    """

    @staticmethod
    def put(username):
        """ HTTP PUT method for User.

            Args:
                master_verify_key (str): NaCl verification key for adding new devices.

            Returns:
                HTTP 422: If the desired username is already registered.

                HTTP 400: If the provided master_verify_key is not a valid NaCl verify
                key.

                (str), HTTP 201: If the user registration was successful.
        """

        parser = reqparse.RequestParser()
        parser.add_argument('master_verify_key',
                            type=str,
                            required=True,
                            help="master_verify_key is either blank or incorrect type.")
        args = parser.parse_args()

        #check if user exists already
        check_user = query_db('''
                              SELECT username
                              FROM users
                              WHERE username=%s;''',
                              (username,),
                              one=True)
        if check_user is not None:
            abort(422, message="username already registered.")

        #check if provided key is a valid key
        try:
            VerifyKey(args['master_verify_key'], encoder=HexEncoder)
        except:
            abort(400,
                  message="The provided master_verify_key is not valid.")

        #otherwise, add user
        query_db('''
                 INSERT INTO users
                 VALUES(%s, %s);''',
                 (username,
                  args['master_verify_key']))
        get_db().commit()

        return "User %s registered successfully." % username, 201
