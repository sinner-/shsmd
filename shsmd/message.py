''' x '''
import json
from base64 import b64encode
from flask_restful import Resource
from flask_restful import reqparse
from flask_restful import abort
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from nacl.public import PublicKey
from nacl.encoding import HexEncoder
from shsmd.db import query_db
from shsmd.db import get_db
from shsmd.util import reconstruct_signed_message

class Message(Resource):
    ''' x '''
    def post(self):
        ''' x '''
        parser = reqparse.RequestParser()
        parser.add_argument('device_verify_key', type=str)
        parser.add_argument('destination_usernames', type=str)
        parser.add_argument('message_public_key', type=str)
        parser.add_argument('message_contents', type=str)
        args = parser.parse_args()

        #check if user exists already
        stored_key = query_db('''
                              SELECT device_verify_key
                              FROM devices
                              WHERE device_verify_key = ?;''',
                              [args['device_verify_key']],
                              one=True)
        if stored_key is None:
            abort(422, message="Username does not exist.")

        destination_usernames = reconstruct_signed_message(args['destination_usernames'])

        message_contents = reconstruct_signed_message(args['message_contents'])

        message_public_key = reconstruct_signed_message(args['message_public_key'])
        try:
            PublicKey(message_public_key.message, encoder=HexEncoder)
        except TypeError:
            abort(400, message='Provided message_public_key is not a valid public key.')

        device_verify_key = VerifyKey(stored_key['device_verify_key'], encoder=HexEncoder)

        try:
            device_verify_key.verify(destination_usernames)
        except BadSignatureError:
            abort(400, message="Signature for provided username is corrupt or invalid.")
        try:
            device_verify_key.verify(message_contents)
        except BadSignatureError:
            abort(400, message="Signature for provided message_contents is corrupt or invalid.")
        try:
            device_verify_key.verify(message_public_key)
        except BadSignatureError:
            abort(400, message="Signature for provided message_public_key is corrupt or invalid.")

        message_id = b64encode(message_contents.signature)
        query_db('''
                 INSERT INTO messages
                 VALUES(?, ?, ?);''',
                 [message_id,
                  b64encode(message_contents.message),
                  b64encode(message_public_key.message)])
        get_db().commit()

        for dest_user in json.loads(destination_usernames.message)['destination_usernames']:

            for row in query_db('''
                                SELECT device_verify_key
                                FROM devices
                                WHERE username=?;''',
                                [dest_user]):
                query_db('''
                         INSERT INTO message_recipients
                         VALUES(?, ?);''',
                         [row['device_verify_key'],
                          message_id])
                get_db().commit()


        return args['device_verify_key'], 201
