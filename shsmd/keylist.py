''' x '''
from flask_restful import Resource
from flask_restful import reqparse
from flask_restful import abort
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from shsmd.db import query_db
from shsmd.util import reconstruct_signed_message

class KeyList(Resource):
    ''' x '''

    def post(self):
        ''' x '''
        parser = reqparse.RequestParser()
        parser.add_argument('device_verify_key', type=str)
        parser.add_argument('destination_username', type=str)
        args = parser.parse_args()

        #check if user exists already
        stored_key = query_db('''
                              SELECT device_verify_key
                              FROM devices
                              WHERE device_verify_key = ?;''',
                              [args['device_verify_key']],
                              one=True)
        if stored_key is None:
            abort(422, message="Device does not exist.")

        destination_username = reconstruct_signed_message(args['destination_username'])

        device_verify_key = VerifyKey(stored_key['device_verify_key'], encoder=HexEncoder)

        try:
            device_verify_key.verify(destination_username)
        except BadSignatureError:
            abort(400,
                  message="Signature for provided username is corrupt or invalid.")

        device_public_keys = []
        for row in query_db('''
                            SELECT device_public_key
                            FROM devices
                            WHERE username=?;''',
                            [destination_username.message]):
            device_public_keys.append(row['device_public_key'])

        return {'device_public_keys': device_public_keys}