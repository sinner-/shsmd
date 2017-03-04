""" shsmd
"""

import json
from flask_restful import Resource
from flask_restful import reqparse
from flask_restful import abort
import nacl.utils
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from shsmd.db.mysql import query_db
from shsmd.db.mysql import get_db
from shsmd.common.util import reconstruct_signed_message

class MessageList(Resource):
    """ flask restful class for delivering all messages for a requested device.

        Currently only handles delivering of messages via HTTP POST.
    """

    def post(self):
        """ message delivery method.

            Args:
                signed_device_verify_key (str): base64 encoded, signed device_verify_key to
                ensure that the user is only fetching messages for devices which they posess
                the full device verification keypair for.

            Returns:
                HTTP 422: If the device_verify_key provided by the user does not exist.

                HTTP 400: If the provided signed_device_verify_key is not signed by the
                correct device_verify_key provided during device registration.

                messages (dict): A dictionary containing all messages to be delivered to
                the requested device.
        """

        parser = reqparse.RequestParser()
        parser.add_argument('signed_device_verify_key',
                            type=str,
                            required=True,
                            help="signed_device_verify_key is either blank or incorrect type.")
        args = parser.parse_args()

        signed_device_verify_key = reconstruct_signed_message(args['signed_device_verify_key'])

        #check if user exists already
        stored_key = query_db('''
                              SELECT device_verify_key
                              FROM devices
                              WHERE device_verify_key = %s;''',
                              (signed_device_verify_key.message,),
                              one=True)
        if stored_key is None:
            abort(422, message="Device does not exist.")

        device_verify_key = VerifyKey(stored_key[0], encoder=HexEncoder)

        try:
            device_verify_key.verify(signed_device_verify_key)
        except nacl.exceptions.BadSignatureError:
            abort(400,
                  message="Signature for provided username is corrupt or invalid.")

        messages = {}
        for row in query_db('''
                            SELECT message_public_key, reply_to, message_contents
                            FROM messages
                            JOIN message_recipients
                            ON messages.message_id = message_recipients.message_id
                            WHERE device_verify_key=%s;''',
                            (signed_device_verify_key.message,)):
            if row is not None:
                messages[row[0]] = json.dumps({'reply_to': row[1], 'message_manifest': row[2]})
                query_db('''
                         DELETE FROM message_recipients
                         WHERE device_verify_key=%s;''',
                         (signed_device_verify_key.message,))
                query_db('''
                         DELETE FROM messages
                         WHERE message_id
                         NOT IN (
                                 SELECT message_id
                                 FROM message_recipients);''')
                get_db().commit()

        return {'messages': messages}
