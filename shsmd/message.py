""" shsmd
"""

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
    """ flask restful class for sending a message to a list of destination usernames.

        Currently only handles sending a message via HTTP POST.
    """

    def post(self):
        """ message sending method.

            Args:
                device_verify_key     (str): NaCl verification key for the device the user
                is sending the query as.
                destination_usernames (str): base64 encoded, signed, JSON encapsulated
                list of destination usernames.
                message_public_key    (str): base64 encoded, signed, ephemeral public
                key that was used to encrypt the message.
                message_contents      (str): base64 encoded, signed message contents.

            Returns:
                HTTP 422: If the device_verify_key provided by the user does not exist.

                HTTP 400: If the provided destination_usernames, message_public_key or
                message_contents is not signed by the correct device_verify_key provided
                during device registration, or if the provided message_public_key is not
                a valid NaCl public key.

                device_verify_key, HTTP 201: If the message was sent successfully.

        """

        parser = reqparse.RequestParser()
        parser.add_argument('device_verify_key',
                            type=str,
                            required=True,
                            help="device_verify_key is either blank or incorrect type.")
        parser.add_argument('destination_usernames',
                            type=str,
                            required=True,
                            help="destination_usernames is either blank or incorrect type.")
        parser.add_argument('message_public_key',
                            type=str,
                            required=True,
                            help="message_public_key is either blank or incorrect type.")
        parser.add_argument('message_contents',
                            type=str,
                            required=True,
                            help="message_contents is either blank or incorrect type.")
        args = parser.parse_args()

        #check if user exists already
        device_record = query_db('''
                                 SELECT username, device_verify_key
                                 FROM devices
                                 WHERE device_verify_key = %s;''',
                                 (args['device_verify_key'],),
                                 one=True)
        if device_record is None:
            abort(422, message="Device does not exist.")
        else:
            stored_key = device_record[1]
            username = device_record[0]

        destination_usernames = reconstruct_signed_message(args['destination_usernames'])

        message_contents = reconstruct_signed_message(args['message_contents'])

        message_public_key = reconstruct_signed_message(args['message_public_key'])
        try:
            PublicKey(message_public_key.message, encoder=HexEncoder)
        except TypeError:
            abort(400, message='Provided message_public_key is not a valid public key.')

        device_verify_key = VerifyKey(stored_key, encoder=HexEncoder)

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

        try:
            user_list = json.loads(destination_usernames.message)
        except ValueError:
            abort(400, message="Provided destination_usernames must be JSON encapsulated.")

        if not isinstance(user_list, list):
            abort(400, message="Provided destination_usernames must be a list.")

        message_id = b64encode(message_contents.signature)
        query_db('''
                 INSERT INTO messages
                 VALUES(%s, %s, %s, %s);''',
                 (message_id,
                  username,
                  b64encode(message_contents.message),
                  b64encode(message_public_key.message)))
        get_db().commit()

        for dest_user in user_list:

            for row in query_db('''
                                SELECT device_verify_key
                                FROM devices
                                WHERE username=%s;''',
                                (dest_user,)):
                query_db('''
                         INSERT INTO message_recipients
                         VALUES(%s, %s);''',
                         (row[0],
                          message_id))
                get_db().commit()


        return args['device_verify_key'], 201
