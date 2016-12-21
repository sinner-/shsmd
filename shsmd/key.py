""" shsmd
"""

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

class Key(Resource):
    """ flask restful class for devices.

        Currently only handles device registration via HTTP POST.
    """

    def post(self):
        """ device registration method.

            Args:
                device_verify_key (str): NaCl verify key for the device.
                device_public_key (str): NaCl public key for the device.

            Returns:
                HTTP 422: If the username the user has requested to register the device
                under does not exist.

                HTTP 400: If device_public_key is not a valid
                NaCl key, or if any of the provided keys are not signed by the device
                verification key provided during device registration.

                HTTP 201: If the key upload was successful.
        """

        parser = reqparse.RequestParser()
        parser.add_argument('device_verify_key',
                            type=str,
                            required=True,
                            help="device_verify_key is either blank or incorrect type.")
        parser.add_argument('device_public_key',
                            type=str,
                            required=True,
                            help="device_public_key is either blank or incorrect type.")
        args = parser.parse_args()

        #check if user exists already
        stored_key = query_db('''
                              SELECT device_verify_key
                              FROM devices
                              WHERE device_verify_key = %s;''',
                              (args['device_verify_key'],),
                              one=True)
        if stored_key is None:
            abort(422, message="Device does not exist.")

        signed_device_public_key = reconstruct_signed_message(args['device_public_key'])
        try:
            PublicKey(signed_device_public_key.message, encoder=HexEncoder)
        except TypeError:
            abort(400,
                  message="The provided device_public_key is not valid.")

        #check to ensure keys are signed with master key
        device_verify_key = VerifyKey(stored_key[0], encoder=HexEncoder)

        try:
            device_verify_key.verify(signed_device_public_key)
        except BadSignatureError:
            abort(400,
                  message="Signature for device_public_key is corrupt or invalid.")

        #otherwise, add device
        query_db('''
                 INSERT INTO pubkeys
                 VALUES(%s, %s);''',
                 (args['device_public_key'],
                  args['device_verify_key']))
        get_db().commit()

        return signed_device_public_key.message, 201
