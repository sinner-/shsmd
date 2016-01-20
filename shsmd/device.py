#!/bin/python
''' x '''
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
    ''' x '''
    def post(self):
        ''' x '''
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str)
        parser.add_argument('device_verify_key', type=str)
        parser.add_argument('device_public_key', type=str)
        args = parser.parse_args()

        #check if user exists already
        #TODO: check for mismatch between existing keys and new keys
        #TODO: e.g. same device_verify_key but new device_public_key
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
