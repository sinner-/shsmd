from binascii import Error as BinasciiError
from flask_restful import Resource
from flask_restful import reqparse
from flask_restful import abort
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from shsmd.db.mysql import query_db
from shsmd.db.mysql import get_db
from shsmd.common.util import reconstruct_signed_message

class Device(Resource):
    """ flask restful class for registering a device against a username.
    """

    @staticmethod
    def post():
        """ HTTP POST method for Device.

            Args:
                username          (str): Username the device will be registered against.
                device_verify_key (str): device_verify_key for the device.

            Returns:
                HTTP 400        : If username or device_verify_key is not provided.
                HTTP 400        : If device_verify_key is not a valid VerifyKey.
                HTTP 400        : If device_verify_key is not signed by correct master_verify_key.
                HTTP 422        : If the username the client has specified does not exists.

                (str), HTTP 201 : If device registration was successful, returns device_verify_key.
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
        args = parser.parse_args()

        #check to make sure user exists already
        stored_key = query_db('''
                              SELECT master_verify_key
                              FROM users
                              WHERE username = %s;''',
                              (args['username'],),
                              one=True)
        if stored_key is None:
            abort(422, message="Username does not exist.")

        #check if device_verify_key is a valid VerifyKey
        signed_device_verify_key = reconstruct_signed_message(args['device_verify_key'])
        try:
            VerifyKey(signed_device_verify_key.message, encoder=HexEncoder)
        except (TypeError, BinasciiError):
            abort(400,
                  message="The provided device_verify_key is not valid.")

        master_verify_key = VerifyKey(stored_key[0], encoder=HexEncoder)

        #signature based authentication of the request
        try:
            master_verify_key.verify(signed_device_verify_key)
        except BadSignatureError:
            abort(400,
                  message="Signature for device_verify_key is corrupt or invalid.")

        #register device into DBMS
        device_verify_key = signed_device_verify_key.message.decode('utf-8')
        query_db('''
                 INSERT INTO devices
                 VALUES(%s, %s);''',
                 (device_verify_key,
                  args['username']))
        get_db().commit()

        return device_verify_key, 201
