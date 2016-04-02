""" shsmd
"""

from flask_restful import Resource
from flask_restful import reqparse
from flask_restful import abort
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from shsmd.db import query_db
from shsmd.util import reconstruct_signed_message

class KeyList(Resource):
    """ flask restful class for fetching the list of each
        device_public_key associated with a user.

        Currently only handles fetching of keys via HTTP POST.
    """

    def post(self):
        """ key fetching method.

            Args:
                device_verify_key    (str): NaCl verification key for the device the user
                is sending the query as.
                destination_username (str): base64 encoded, signed destination username.

            Returns:
                HTTP 422: If the device_verify_key provided by the user does not exist.

                HTTP 400: If the provided destination_username is not signed by the
                correct device_verify_key provided during device registration.

                device_public_keys (dict): A dictionary containing the list of all
                device_public_key entries that corresponded to the requested user.

        """

        parser = reqparse.RequestParser()
        parser.add_argument('device_verify_key',
                            type=str,
                            required=True,
                            help="device_verify_key is either blank or incorrect type.")
        parser.add_argument('destination_username',
                            type=str,
                            required=True,
                            help="destination_username is either blank or incorrect type.")
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
        for verify_key in query_db('''
                            SELECT device_verify_key
                            FROM devices
                            WHERE username=?;''',
                            [destination_username.message]):
            row = query_db('''
                           SELECT device_public_key
                           FROM pubkeys
                           WHERE device_verify_key=?;''',
                           [verify_key[0]],
                           one=True)
            device_public_keys.append(row['device_public_key'])

        return {'device_public_keys': device_public_keys}
