from binascii import Error as BinasciiError
from flask_restful import Resource
from flask_restful import reqparse
from flask_restful import abort
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from nacl.public import PublicKey
from nacl.encoding import HexEncoder
from shsmd.db.mysql import query_db
from shsmd.db.mysql import get_db
from shsmd.common.util import reconstruct_signed_message

class Key(Resource):
    """ flask restful class for registering public keys against a device.
    """

    @staticmethod
    def post():
        """ HTTP POST method for Key.

            Args:
                device_verify_key (str): device_verify_key for the device.
                device_public_key (str): device_public_key for the device.

            Returns:
                HTTP 400        : If device_verify_key or device_public_key is not provided.
                HTTP 400        : If device_public_key is not a valid PublicKey.
                HTTP 400        : If device_public_key is not signed by correct device_verify_key.
                HTTP 422        : If the device the client has specified does not exist.

                (str), HTTP 201 : If the key upload was successful.
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

        #check to make sure device exists already
        stored_key = query_db('''
                              SELECT device_verify_key
                              FROM devices
                              WHERE device_verify_key = %s;''',
                              (args['device_verify_key'],),
                              one=True)
        if stored_key is None:
            abort(422, message="Device does not exist.")

        #check if device_public_key is a valid PublicKey
        signed_device_public_key = reconstruct_signed_message(args['device_public_key'])
        try:
            PublicKey(signed_device_public_key.message, encoder=HexEncoder)
        except (TypeError, BinasciiError):
            abort(400,
                  message="The provided device_public_key is not valid.")

        device_verify_key = VerifyKey(stored_key[0], encoder=HexEncoder)

        #signature based authentication of the request
        try:
            device_verify_key.verify(signed_device_public_key)
        except BadSignatureError:
            abort(400,
                  message="Signature for device_public_key is corrupt or invalid.")

        #register public key into DBMS
        query_db('''
                 INSERT INTO pubkeys
                 VALUES(%s, %s);''',
                 (args['device_public_key'],
                  args['device_verify_key']))
        get_db().commit()

        return signed_device_public_key.message.decode('utf-8'), 201
