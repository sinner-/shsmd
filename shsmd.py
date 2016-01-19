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
from json import loads as jsonloads
from contextlib import closing
import sqlite3
import nacl.utils
from nacl.signing import SignedMessage
from nacl.signing import VerifyKey
from nacl.public import PublicKey
from nacl.encoding import HexEncoder
from nacl.encoding import RawEncoder
from flask import Flask
from flask import request
from flask import jsonify
from flask_restful import abort

app = Flask(__name__)

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

    db_path = 'shsmd.db'
    conn = sqlite3.connect(db_path)

    #check if user exists already
    with closing(conn.cursor()) as cursor:
        cursor.execute('''
                       SELECT username
                       FROM users
                       WHERE username=?;''',
                       (request.json['username'],))
        exists = cursor.fetchone()
        if exists is not None:
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
    with conn:
        with closing(conn.cursor()) as cursor:
            cursor.execute('''
                           INSERT INTO users
                           VALUES(?, ?);''',
                           (request.json['username'],
                            request.json['master_verify_key']))

    return jsonify({'username': request.json['username']}), 201

def reconstruct_signed_message(signed_message):
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

    db_path = 'shsmd.db'
    conn = sqlite3.connect(db_path)

    #check if user exists already
    #TODO: check for mismatch between existing keys and new keys
    #TODO: e.g. same device_verify_key but new device_public_key
    with closing(conn.cursor()) as cursor:
        cursor.execute('''
                       SELECT master_verify_key
                       FROM users
                       WHERE username=?;''',
                       (request.json['username'],))
        exists = cursor.fetchone()
        if exists is None:
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
    master_verify_key = VerifyKey(exists[0], encoder=HexEncoder)

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
    with conn:
        with closing(conn.cursor()) as cursor:
            cursor.execute('''
                           INSERT INTO devices
                           VALUES(?, ?, ?);''',
                           (request.json['username'],
                            device_verify_key.message,
                            device_public_key.message))

    return jsonify({'username': request.json['username']}), 201

@app.route('/api/v1.0/get-device-key', methods=['POST'])
def get_device_key():

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

    db_path = 'shsmd.db'
    conn = sqlite3.connect(db_path)

    #check if user exists already
    with closing(conn.cursor()) as cursor:
        cursor.execute('''
                       SELECT device_verify_key
                       FROM devices
                       WHERE username=?;''',
                       (request.json['username'],))
        exists = cursor.fetchone()
        if exists is None:
            abort(422, message="Username does not exist.")

    destination_username = reconstruct_signed_message(request.json['destination_username'])

    device_verify_key = VerifyKey(exists[0], encoder=HexEncoder)

    try:
        device_verify_key.verify(destination_username)
    except nacl.exceptions.BadSignatureError:
        abort(400,
              message="Signature for provided username is corrupt or invalid.")

    device_public_keys = []
    with closing(conn.cursor()) as cursor:
        for row in cursor.execute('''
                                  SELECT device_public_key
                                  FROM devices
                                  WHERE username=?;''',
                                  (destination_username.message,)):
            device_public_keys.append(row[0])

    return jsonify({'device_public_keys': device_public_keys}), 200

@app.route('/api/v1.0/send-message', methods=['POST'])
def send_message():
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

    db_path = 'shsmd.db'
    conn = sqlite3.connect(db_path)

    #check if user exists already
    with closing(conn.cursor()) as cursor:
        cursor.execute('''
                       SELECT device_verify_key
                       FROM devices
                       WHERE username=?;''',
                       (request.json['username'],))
        exists = cursor.fetchone()
        if exists is None:
            abort(422, message="Username does not exist.")

    destination_usernames = reconstruct_signed_message(request.json['destination_usernames'])

    message_contents = reconstruct_signed_message(request.json['message_contents'])

    message_public_key = reconstruct_signed_message(request.json['message_public_key'])
    try:
        PublicKey(message_public_key.message, encoder=HexEncoder)
    except TypeError:
        abort(400, message='Provided message_public_key is not a valid public key.')

    device_verify_key = VerifyKey(exists[0], encoder=HexEncoder)

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
    with conn:
        with closing(conn.cursor()) as cursor:
            cursor.execute('''
                           INSERT INTO messages
                           VALUES(?, ?, ?);''',
                           (message_id,
                            b64encode(message_contents.message),
                            b64encode(message_public_key.message)))

    for destination_username in jsonloads(destination_usernames.message)['destination_usernames']:

        rows = []
        with closing(conn.cursor()) as cursor:
            for row in cursor.execute('''
                                      SELECT device_verify_key
                                      FROM devices
                                      WHERE username=?;''',
                                      (destination_username,)):
                rows.append((row[0], message_id))

        with conn:
            with closing(conn.cursor()) as cursor:
                cursor.executemany('''
                                   INSERT INTO message_recipients
                                   VALUES(?, ?);''',
                                   (rows))

    return jsonify({'username': request.json['username']}), 201

@app.route('/api/v1.0/get-messages', methods=['POST'])
def get_messages():

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

    db_path = 'shsmd.db'
    conn = sqlite3.connect(db_path)

    #check if user exists already
    with closing(conn.cursor()) as cursor:
        cursor.execute('''
                       SELECT device_verify_key
                       FROM devices
                       WHERE username=?;''',
                       (request.json['username'],))
        exists = cursor.fetchone()
        if exists is None:
            abort(422, message="Username does not exist.")

    signed_device_verify_key = reconstruct_signed_message(request.json['signed_device_verify_key'])

    device_verify_key = VerifyKey(exists[0], encoder=HexEncoder)

    try:
        device_verify_key.verify(signed_device_verify_key)
    except nacl.exceptions.BadSignatureError:
        abort(400,
              message="Signature for provided username is corrupt or invalid.")

    with closing(conn.cursor()) as cursor:
        exists = None
        messages = {}
        for row in cursor.execute('''
                                  SELECT message_public_key, message_contents
                                  FROM messages
                                  JOIN message_recipients
                                  ON messages.message_id = message_recipients.message_id
                                  WHERE device_verify_key=?;''',
                                  (signed_device_verify_key.message,)):
            if row is not None:
                messages[row[0]] = row[1]
            #TODO: delete message from database

    return jsonify({'messages': messages}), 200

if __name__ == '__main__':
    app.run(debug=True)
