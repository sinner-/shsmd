''' x '''
from flask_restful import Resource
from flask_restful import reqparse
from flask_restful import abort
import nacl.utils
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from shsmd.db import query_db
from shsmd.util import reconstruct_signed_message

class MessageList(Resource):
    ''' x '''
    def post(self):
        ''' x '''
        parser = reqparse.RequestParser()
        parser.add_argument('device_verify_key', type=str)
        parser.add_argument('signed_device_verify_key', type=str)
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

        signed_device_verify_key = reconstruct_signed_message(args['signed_device_verify_key'])

        device_verify_key = VerifyKey(stored_key['device_verify_key'], encoder=HexEncoder)

        try:
            device_verify_key.verify(signed_device_verify_key)
        except nacl.exceptions.BadSignatureError:
            abort(400,
                  message="Signature for provided username is corrupt or invalid.")

        messages = {}
        for row in query_db('''
                            SELECT message_public_key, message_contents
                            FROM messages
                            JOIN message_recipients
                            ON messages.message_id = message_recipients.message_id
                            WHERE device_verify_key=?;''',
                            [signed_device_verify_key.message]):
            if row is not None:
                messages[row[0]] = row[1]
                #TODO: delete message from database

        return {'messages': messages}
