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

class Device(Resource):
    """ flask restful class for devices.

        Currently only handles device registration via HTTP POST.
    """

    def post(self):
        """ device registration method.

            Args:
                username          (str): Username the device will be registered against.
                device_verify_key (str): NaCl verification key for the device.
                device_public_key (str): NaCl public key for the device.

            Returns:
                HTTP 422: If the username the user has requested to register the device
                under does not exist.

                HTTP 400: If either device_public_key or device_verify_key is not a valid
                NaCl key, or if any of the provided keys are not signed by the master
                verification key provided during user registration.

                device_verify_key, HTTP 201: If the device registration was successful.
        """

        parser = reqparse.RequestParser()
        parser.add_argument('username',
                            type=str,
                            required=True,
                            help="username is either blank or incorrect type.")
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
                              SELECT master_verify_key
                              FROM users
                              WHERE username = ?;''',
                              [args['username']],
                              one=True)
        if stored_key is None:
            abort(422, message="Username does not exist.")

        #check if input is valid
        device_verify_key = reconstruct_signed_message(args['device_verify_key'])
        try:
            VerifyKey(device_verify_key.message, encoder=HexEncoder)
        except TypeError:
            abort(400,
                  message="The provided device_verify_key is not valid.")

        device_public_key = reconstruct_signed_message(args['device_public_key'])
        try:
            PublicKey(device_public_key.message, encoder=HexEncoder)
        except TypeError:
            abort(400,
                  message="The provided device_public_key is not valid.")

        #check to ensure keys are signed with master key
        master_verify_key = VerifyKey(stored_key['master_verify_key'], encoder=HexEncoder)

        try:
            master_verify_key.verify(device_verify_key)
        except BadSignatureError:
            abort(400,
                  message="Signature for device_verify_key is corrupt or invalid.")
        try:
            master_verify_key.verify(device_public_key)
        except BadSignatureError:
            abort(400,
                  message="Signature for device_public_key is corrupt or invalid.")

        #otherwise, add device
        query_db('''
                 INSERT INTO devices
                 VALUES(?, ?, ?);''',
                 [device_verify_key.message,
                  args['username'],
                  device_public_key.message])
        get_db().commit()

        return device_verify_key.message, 201
