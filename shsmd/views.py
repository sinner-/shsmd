#!bin/python
# -*- coding: utf-8 -*-
"""
    shsmd
    ~~~~~~~~~~~~~~

    Self Hosted Secure Messaging Daemon

    :copyright: (c) 2015 by Sina Sadeghi
    :license: GPLv2, see LICENSE for more details.
"""

from base64 import b64decode
from base64 import b64encode
import json
import nacl.utils
from nacl.signing import SignedMessage
from nacl.signing import VerifyKey
from nacl.public import PublicKey
from nacl.encoding import HexEncoder
from nacl.encoding import RawEncoder
from flask import request
from flask_restful import abort
from shsmd import app
from shsmd.db import get_db
from shsmd.db import query_db

@app.route('/api/v1.0/register', methods=['POST'])
def register():
    """Registers the username and associated master verify key

    Yields:
        201 (flask HTTP response code): Successful user registration.
        user (json): json containing username and master_verify_key

    Example:
        curl -i -H "Content-Type: application/json" \
             -X POST \
             -d '{"username":"testuser", "master_verify_key":"HEX_ENC_VERIFY_KEY"}' \
             http://localhost:5000/todo/api/v1.0/register
    """

    #input validation
    if not request.json:
        abort(400,
              message="JSON request body missing or incorrect Content-Type.")
    if 'username' not in request.json:
        abort(400,
              message="JSON request missing username field.")
    if len(request.json['username']) == 0:
        abort(404,
              message="username field must contain at least one character.")
    if 'master_verify_key' not in request.json:
        abort(400,
              message="JSON request missing master_verify_key field.")

    #check if user exists already
    username = query_db('''
                        SELECT username
                        FROM users
                        WHERE username = ?;''',
                        [request.json['username']],
                        one=True)
    if username is not None:
        abort(422, message="username already registered.")

    #check if provided key is a valid key
    try:
        master_verify_key = VerifyKey(
            request.json['master_verify_key'],
            encoder=HexEncoder)
    except TypeError:
        abort(400,
              message="The provided master_verify_key is not valid.")

    #otherwise, add user
    query_db('''
             INSERT INTO users
             VALUES(?, ?);''',
             [request.json['username'],
              request.json['master_verify_key']])
    get_db().commit()

    return json.dumps({'username': request.json['username']}), 201

def reconstruct_signed_message(signed_message):
    ''' xxx '''
    tmp_encoder = RawEncoder
    try:
        tmp_signed_message = tmp_encoder.encode(b64decode(signed_message))
        recon_signed_message = SignedMessage._from_parts(
            tmp_encoder.encode(
                tmp_signed_message[:nacl.bindings.crypto_sign_BYTES]),
            tmp_encoder.encode(
                tmp_signed_message[nacl.bindings.crypto_sign_BYTES:]),
            tmp_signed_message)
    except TypeError:
        abort(400,
              message="The provided signed_message is not valid.")

    return recon_signed_message


@app.route('/api/v1.0/add-device', methods=['POST'])
def add_device():
    """Registers device encryption and signing keys against a username.

    Yields:
        201 (flask HTTP response code): Successful device registration
        user (json): json containing username, device_verify_key and device_public_key

    Example:
        curl -i -H "Content-Type: application/json" \
             -X POST \
             -d '{"username":"testuser", \
                  "device_verify_key":"HEX_ENC_VERIFY_KEY"}' \
                  "device_public_key":"HEX_ENC_PUBLIC_KEY"}' \
             http://localhost:5000/todo/api/v1.0/add-device
    """

    if not request.json:
        abort(400,
              message="JSON request body missing or incorrect Content-Type.")
    if 'username' not in request.json:
        abort(400,
              message="JSON request missing username field.")
    if len(request.json['username']) == 0:
        abort(404,
              message="username field must contain at least one character.")
    if 'device_verify_key' not in request.json:
        abort(400,
              message="JSON request missing device_verify_key field.")
    if 'device_public_key' not in request.json:
        abort(400,
              message="JSON request missing device_public_key field.")

    #check if user exists already
    #TODO: check for mismatch between existing keys and new keys
    #TODO: e.g. same device_verify_key but new device_public_key
    stored_key = query_db('''
                          SELECT master_verify_key
                          FROM users
                          WHERE username = ?;''',
                          [request.json['username']],
                          one=True)
    if stored_key is None:
        abort(422, message="Username does not exist.")

    #check if input is valid
    device_verify_key = reconstruct_signed_message(request.json['device_verify_key'])
    try:
        VerifyKey(device_verify_key.message, encoder=HexEncoder)
    except TypeError:
        abort(400,
              message="The provided device_verify_key is not valid.")

    device_public_key = reconstruct_signed_message(request.json['device_public_key'])
    try:
        PublicKey(device_public_key.message, encoder=HexEncoder)
    except TypeError:
        abort(400,
              message="The provided device_public_key is not valid.")

    #check to ensure keys are signed with master key
    master_verify_key = VerifyKey(stored_key['master_verify_key'], encoder=HexEncoder)

    try:
        master_verify_key.verify(device_verify_key)
    except nacl.exceptions.BadSignatureError:
        abort(400,
              message="Signature for device_verify_key is corrupt or invalid.")
    try:
        master_verify_key.verify(device_public_key)
    except nacl.exceptions.BadSignatureError:
        abort(400,
              message="Signature for device_public_key is corrupt or invalid.")

    #otherwise, add device
    query_db('''
             INSERT INTO devices
             VALUES(?, ?, ?);''',
             [device_verify_key.message,
              request.json['username'],
              device_public_key.message])
    get_db().commit()

    return json.dumps({'username': request.json['username']}), 201

@app.route('/api/v1.0/get-device-key', methods=['POST'])
def get_device_key():

    ''' xxx '''
    if not request.json:
        abort(400,
              message="JSON request body missing or incorrect Content-Type.")
    if 'username' not in request.json:
        abort(400,
              message="JSON request missing username field.")
    if len(request.json['username']) == 0:
        abort(404,
              message="username field must contain at least one character.")
    if 'destination_username' not in request.json:
        abort(400,
              message="JSON request missing destination_username field.")

    #check if user exists already
    stored_key = query_db('''
                          SELECT device_verify_key
                          FROM devices
                          WHERE username = ?;''',
                          [request.json['username']],
                          one=True)
    if stored_key is None:
        abort(422, message="Username does not exist.")

    destination_username = reconstruct_signed_message(request.json['destination_username'])

    device_verify_key = VerifyKey(stored_key['device_verify_key'], encoder=HexEncoder)

    try:
        device_verify_key.verify(destination_username)
    except nacl.exceptions.BadSignatureError:
        abort(400,
              message="Signature for provided username is corrupt or invalid.")

    device_public_keys = []
    for row in query_db('''
                        SELECT device_public_key
                        FROM devices
                        WHERE username=?;''',
                        [destination_username.message]):
        device_public_keys.append(row['device_public_key'])

    return json.dumps({'device_public_keys': device_public_keys}), 200

@app.route('/api/v1.0/send-message', methods=['POST'])
def send_message():
    ''' xxx '''
    if not request.json:
        abort(400,
              message="JSON request body missing or incorrect Content-Type.")
    if 'username' not in request.json:
        abort(400,
              message="JSON request missing username field.")
    if len(request.json['username']) == 0:
        abort(404,
              message="username field must contain at least one character.")
    if 'destination_usernames' not in request.json:
        abort(400,
              message="JSON request missing destination_username field.")
    if 'message_contents' not in request.json:
        abort(400,
              message="JSON request missing message_contents field.")
    if 'message_public_key' not in request.json:
        abort(400,
              message="JSON request missing message_public_key field.")

    #check if user exists already
    stored_key = query_db('''
                          SELECT device_verify_key
                          FROM devices
                          WHERE username = ?;''',
                          [request.json['username']],
                          one=True)
    if stored_key is None:
        abort(422, message="Username does not exist.")

    destination_usernames = reconstruct_signed_message(request.json['destination_usernames'])

    message_contents = reconstruct_signed_message(request.json['message_contents'])

    message_public_key = reconstruct_signed_message(request.json['message_public_key'])
    try:
        PublicKey(message_public_key.message, encoder=HexEncoder)
    except TypeError:
        abort(400, message='Provided message_public_key is not a valid public key.')

    device_verify_key = VerifyKey(stored_key['device_verify_key'], encoder=HexEncoder)

    try:
        device_verify_key.verify(destination_usernames)
    except nacl.exceptions.BadSignatureError:
        abort(400, message="Signature for provided username is corrupt or invalid.")
    try:
        device_verify_key.verify(message_contents)
    except nacl.exceptions.BadSignatureError:
        abort(400, message="Signature for provided message_contents is corrupt or invalid.")
    try:
        device_verify_key.verify(message_public_key)
    except nacl.exceptions.BadSignatureError:
        abort(400, message="Signature for provided message_public_key is corrupt or invalid.")

    message_id = b64encode(message_contents.signature)
    query_db('''
             INSERT INTO messages
             VALUES(?, ?, ?);''',
             [message_id,
              b64encode(message_contents.message),
              b64encode(message_public_key.message)])
    get_db().commit()

    for destination_username in json.loads(destination_usernames.message)['destination_usernames']:

        for row in query_db('''
                            SELECT device_verify_key
                            FROM devices
                            WHERE username=?;''',
                            [destination_username]):
            query_db('''
                     INSERT INTO message_recipients
                     VALUES(?, ?);''',
                     [row['device_verify_key'],
                      message_id])
            get_db().commit()


    return json.dumps({'username': request.json['username']}), 201

@app.route('/api/v1.0/get-messages', methods=['POST'])
def get_messages():

    ''' xxx '''
    if not request.json:
        abort(400,
              message="JSON request body missing or incorrect Content-Type.")
    if 'username' not in request.json:
        abort(400,
              message="JSON request missing username field.")
    if len(request.json['username']) == 0:
        abort(404,
              message="username field must contain at least one character.")
    if 'signed_device_verify_key' not in request.json:
        abort(400,
              message="JSON request missing signed_device_verify_key field.")

    #check if user exists already
    stored_key = query_db('''
                          SELECT device_verify_key
                          FROM devices
                          WHERE username = ?;''',
                          [request.json['username']],
                          one=True)
    if stored_key is None:
        abort(422, message="Username does not exist.")

    signed_device_verify_key = reconstruct_signed_message(request.json['signed_device_verify_key'])

    device_verify_key = VerifyKey(stored_key['device_verify_key'], encoder=HexEncoder)

    try:
        device_verify_key.verify(signed_device_verify_key)
    except nacl.exceptions.BadSignatureError:
        abort(400,
              message="Signature for provided username is corrupt or invalid.")

    messages = {}
    for row in query_db('''
                        SELECT message_public_key, message_contents
                        FROM messages
                        JOIN message_recipients
                        ON messages.message_id = message_recipients.message_id
                        WHERE device_verify_key=?;''',
                        [signed_device_verify_key.message]):
        if row is not None:
            messages[row[0]] = row[1]
            #TODO: delete message from database

    return json.dumps({'messages': messages}), 200
