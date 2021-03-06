from json import dumps
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
    """

    @staticmethod
    def get(username, device_id):
        """ HTTP GET for MessageList

            Args:
                device_verify_key    (str): signed device_verify_key to authenticate client.

            Returns:
                HTTP 400    : If device_verify_key is not provided.
                HTTP 400    : If device_verify_key is not signed by correct client.
                HTTP 422    : If device_verify_key does not exist.
                (dict)      : Dictionary of all messages to be delivered to the requested device.
        """

        parser = reqparse.RequestParser()
        parser.add_argument('device-verify-key',
                            location='headers',
                            type=str,
                            required=True,
                            help="device_verify_key is either blank or incorrect type.")
        args = parser.parse_args()

        signed_device_verify_key = reconstruct_signed_message(args['device-verify-key'])

        #check to make sure clients device exists.
        stored_key = query_db('''
                              SELECT device_verify_key
                              FROM devices
                              WHERE device_verify_key = %s
                              AND username = %s;''',
                              (device_id, username),
                              one=True)
        if stored_key is None:
            abort(422, message="Device does not exist.")

        device_verify_key = VerifyKey(stored_key[0], encoder=HexEncoder)

        #signature based authentication of the request
        try:
            device_verify_key.verify(signed_device_verify_key)
        except nacl.exceptions.BadSignatureError:
            abort(400,
                  message="Signature for provided username is corrupt or invalid.")

        if device_id != signed_device_verify_key.message.decode('utf-8'):
            abort(400,
                  message="The device_verify_key does not match supplied device ID.")

        #fetch requested messages from DBMS
        messages = {}
        for row in query_db('''
                            SELECT message_public_key, reply_to, message_contents, messages.message_id
                            FROM messages
                            JOIN message_recipients
                            ON messages.message_id = message_recipients.message_id
                            WHERE device_verify_key=%s;''',
                            (device_id,)):
            if row is not None:
                messages[row[0]] = dumps({'reply_to': row[1], 'message_manifest': row[2]})
                query_db('''
                         DELETE FROM message_recipients
                         WHERE message_id=%s
                         AND device_verify_key=%s;''',
                         (row[3], device_id,))
                query_db('''
                         DELETE FROM messages
                         WHERE message_id
                         NOT IN (
                                 SELECT message_id
                                 FROM message_recipients);''')

                get_db().commit()

        return messages
