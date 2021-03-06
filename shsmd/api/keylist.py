from flask_restful import Resource
from flask_restful import reqparse
from flask_restful import abort
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from shsmd.db.mysql import query_db
from shsmd.common.util import reconstruct_signed_message

class KeyList(Resource):
    """ flask restful class for fetching device_public_keys associated with a users devices.
    """

    @staticmethod
    def get(username):
        """ HTTP GET method for KeyList

            Args:
                device-verify-key    (str): signed device_verify_key to authenticate client.

            Returns:
                HTTP 400    : If device_verify_key or username is not provided.
                HTTP 400    : If username is not signed by the correct client.
                HTTP 422    : If the device_verify_key provided by the user does not exist.

                (dict)      : List of all device_public_key entries for the requested user.

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
                              WHERE device_verify_key = %s;''',
                              (signed_device_verify_key.message.decode('utf-8')),
                              one=True)
        if stored_key is None:
            abort(422, message="Device does not exist.")

        device_verify_key = VerifyKey(stored_key[0], encoder=HexEncoder)

        #signature based authentication of the request
        try:
            device_verify_key.verify(signed_device_verify_key)
        except BadSignatureError:
            abort(400,
                  message="Signature for provided device_verify_key is corrupt or invalid.")

        #fetch the requested keys from DBMS
        device_public_keys = []
        for verify_key in query_db('''
                                   SELECT device_verify_key
                                   FROM devices
                                   WHERE username=%s;''',
                                   (username,)):
            row = query_db('''
                           SELECT device_public_key
                           FROM pubkeys
                           WHERE device_verify_key=%s;''',
                           (verify_key[0],),
                           one=True)
            device_public_keys.append(row[0])

        return device_public_keys
