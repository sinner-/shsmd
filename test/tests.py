import os
import unittest
import tempfile
import json
from base64 import b64encode
from base64 import b64decode
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from nacl.public import PrivateKey
import flask.wrappers
import shsmd.api

class ShsmdTestCase(unittest.TestCase):
    def setUp(self):
        self.db_fd, shsmd.api.app.config['DATABASE'] = tempfile.mkstemp()
        shsmd.api.app.config['TESTING'] = True
        self.app = shsmd.api.app.test_client()
        shsmd.db.mysql.drop_schema()
        shsmd.db.mysql.create_schema()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(shsmd.api.app.config['DATABASE'])

    def register_user(self, username, master_verify_key):
        return self.app.post('/api/v1.0/user',
                             data={'username': username,
                                   'master_verify_key': master_verify_key})

    def register_device(self, username, device_verify_key):
        return self.app.post('/api/v1.0/device',
                             data={'username': username,
                                   'device_verify_key': device_verify_key})

    def add_key(self, device_verify_key, device_public_key):
        return self.app.post('/api/v1.0/key',
                             data={'device_verify_key': device_verify_key,
                                   'device_public_key': device_public_key})

    def fetch_key(self, device_verify_key, destination_username):
        return self.app.post('/api/v1.0/keylist',
                             data={'device_verify_key': device_verify_key,
                                   'destination_username': destination_username})

    def fetch_device(self, device_verify_key, destination_username):
        return self.app.post('/api/v1.0/devicelist',
                             data={'device_verify_key': device_verify_key,
                                   'destination_username': destination_username})

    def send_message(self, device_verify_key, destination_usernames, message_public_key, message_contents):
        return self.app.post('/api/v1.0/message',
                             data={'device_verify_key': device_verify_key,
                                   'destination_usernames': destination_usernames,
                                   'message_public_key': message_public_key,
                                   'message_contents': message_contents})

    def get_messages(self, signed_device_verify_key):
        return self.app.post('/api/v1.0/messagelist',
                             data={'signed_device_verify_key': signed_device_verify_key})

    def test_register_user_empty_user(self):
        rv = self.register_user(None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'username' in response['message'].keys()
        assert response['message']['username'] == "username is either blank or incorrect type."

    def test_register_user_empty_key(self):
        rv = self.register_user('testuser', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'master_verify_key' in response['message'].keys()
        assert response['message']['master_verify_key'] == "master_verify_key is either blank or incorrect type."

    def test_register_user_invalid_master_verify_key(self):
        rv = self.register_user('testuser', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided master_verify_key is not valid."

    def test_register_user_valid(self):
        username = 'testuser'
        test_key = SigningKey.generate().verify_key.encode(encoder=HexEncoder)
        rv = self.register_user(username, test_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 201
        assert response == username

    def test_register_user_existing_username(self):
        test_key = SigningKey.generate().verify_key.encode(encoder=HexEncoder)
        self.register_user('testuser', test_key)
        rv = self.register_user('testuser', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "username already registered."

    def test_register_device_empty_user(self):
        rv = self.register_device(None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'username' in response['message'].keys()
        assert response['message']['username'] == "username is either blank or incorrect type."

    def test_register_device_empty_device_verify_key(self):
        rv = self.register_device('testuser', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_register_device_nonexistent_username(self):
        rv = self.register_device('testuser', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Username does not exist."

    def test_register_device_unsigned_device_verify_key(self):
        username = 'testuser'
        master_verify_key = SigningKey.generate().verify_key.encode(encoder=HexEncoder)
        rv = self.register_user(username, master_verify_key)
        rv = self.register_device(username, 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_register_device_invalid_device_verify_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        signed_invalid_device_verify_key = b64encode(master_signing_key.sign('a'))
        rv = self.register_device(username, signed_invalid_device_verify_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided device_verify_key is not valid."

    def test_register_device_badsigned_device_verify_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        badsigned_device_verify_key = b64encode(device_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        rv = self.register_device(username, badsigned_device_verify_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for device_verify_key is corrupt or invalid."

    def test_register_device_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        rv = self.register_device(username, valid_device_verify_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 201
        assert response == device_signing_key.verify_key.encode(encoder=HexEncoder)

    def test_add_key_empty_device_verify_key(self):
        rv = self.add_key(None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_add_key_empty_device_public_key(self):
        rv = self.add_key('a', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_public_key' in response['message'].keys()
        assert response['message']['device_public_key'] == "device_public_key is either blank or incorrect type."

    def test_add_key_nonexistent_device(self):
        rv = self.add_key('a','a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Device does not exist."

    def test_add_key_unsigned_device_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        rv = self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_add_key_invalid_device_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        rv = self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided device_public_key is not valid."

    def test_add_key_badsigned_device_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        rv = self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(master_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder))))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for device_public_key is corrupt or invalid."

    def test_add_key_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        rv = self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder))))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 201

    def test_fetch_key_empty_device_verify_key(self):
        rv = self.fetch_key(None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_fetch_key_empty_destination_username(self):
        rv = self.fetch_key('a', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'destination_username' in response['message'].keys()
        assert response['message']['destination_username'] == "destination_username is either blank or incorrect type."

    def test_fetch_key_nonexistent_device_verify_key(self):
        rv = self.fetch_key('a', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Device does not exist."

    def test_fetch_key_unsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        valid_device_public_key = b64encode(master_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.fetch_key(device_signing_key.verify_key.encode(encoder=HexEncoder), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_fetch_key_unsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.fetch_key(device_signing_key.verify_key.encode(encoder=HexEncoder), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_fetch_key_badsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.fetch_key(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(master_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided username is corrupt or invalid."

    def test_fetch_key_nonexistent_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key.encode(encoder=HexEncoder)
        valid_device_public_key = b64encode(device_signing_key.sign(public_key))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.fetch_key(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 200
        assert 'device_public_keys' in response.keys()
        assert len(response['device_public_keys']) == 0

    def test_fetch_key_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key.encode(encoder=HexEncoder)
        valid_device_public_key = b64encode(device_signing_key.sign(public_key))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.fetch_key(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign(username)))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 200
        assert 'device_public_keys' in response.keys()
        assert shsmd.common.util.reconstruct_signed_message(response['device_public_keys'][0]).message == public_key

    def test_fetch_key_valid_multiple(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device1_signing_key = SigningKey.generate()
        device2_signing_key = SigningKey.generate()
        valid_device1_verify_key = b64encode(master_signing_key.sign(device1_signing_key.verify_key.encode(encoder=HexEncoder)))
        valid_device2_verify_key = b64encode(master_signing_key.sign(device2_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key1 = PrivateKey.generate().public_key.encode(encoder=HexEncoder)
        public_key2 = PrivateKey.generate().public_key.encode(encoder=HexEncoder)
        valid_device1_public_key = b64encode(device1_signing_key.sign(public_key1))
        valid_device2_public_key = b64encode(device2_signing_key.sign(public_key2))
        self.register_device(username, valid_device1_verify_key)
        self.register_device(username, valid_device2_verify_key)
        self.add_key(device1_signing_key.verify_key.encode(encoder=HexEncoder), valid_device1_public_key)
        self.add_key(device2_signing_key.verify_key.encode(encoder=HexEncoder), valid_device2_public_key)
        rv = self.fetch_key(device1_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device1_signing_key.sign(username)))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 200
        assert 'device_public_keys' in response.keys()
        assert valid_device1_public_key in response['device_public_keys']
        assert valid_device2_public_key in response['device_public_keys']


    def test_fetch_device_empty_device_verify_key(self):
        rv = self.fetch_device(None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_fetch_device_empty_destination_username(self):
        rv = self.fetch_device('a', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'destination_username' in response['message'].keys()
        assert response['message']['destination_username'] == "destination_username is either blank or incorrect type."

    def test_fetch_device_nonexistent_device_verify_key(self):
        rv = self.fetch_device('a', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Device does not exist."

    def test_fetch_device_unsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        rv = self.fetch_device(device_signing_key.verify_key.encode(encoder=HexEncoder), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_fetch_device_unsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        rv = self.fetch_device(device_signing_key.verify_key.encode(encoder=HexEncoder), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_fetch_device_badsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        rv = self.fetch_device(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(master_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided username is corrupt or invalid."

    def test_fetch_device_nonexistent_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        rv = self.fetch_device(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 200
        assert 'device_verify_keys' in response.keys()
        assert len(response['device_verify_keys']) == 0

    def test_fetch_device_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        rv = self.fetch_device(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign(username)))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 200
        assert 'device_verify_keys' in response.keys()
        assert response['device_verify_keys'][0] == device_signing_key.verify_key.encode(encoder=HexEncoder)

    def test_fetch_device_valid_multiple(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device1_signing_key = SigningKey.generate()
        device2_signing_key = SigningKey.generate()
        valid_device1_verify_key = b64encode(master_signing_key.sign(device1_signing_key.verify_key.encode(encoder=HexEncoder)))
        valid_device2_verify_key = b64encode(master_signing_key.sign(device2_signing_key.verify_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device1_verify_key)
        self.register_device(username, valid_device2_verify_key)
        rv = self.fetch_device(device1_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device1_signing_key.sign(username)))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 200
        assert 'device_verify_keys' in response.keys()
        assert device1_signing_key.verify_key.encode(encoder=HexEncoder) in response['device_verify_keys']
        assert device2_signing_key.verify_key.encode(encoder=HexEncoder) in response['device_verify_keys']

    def test_send_message_empty_device_verify_key(self):
        rv = self.send_message(None, None, None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_send_message_empty_destination_usernames(self):
        rv = self.send_message('a', None, None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'destination_usernames' in response['message'].keys()
        assert response['message']['destination_usernames'] == "destination_usernames is either blank or incorrect type."

    def test_send_message_empty_message_public_key(self):
        rv = self.send_message('a', 'a', None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'message_public_key' in response['message'].keys()
        assert response['message']['message_public_key'] == "message_public_key is either blank or incorrect type."

    def test_send_message_empty_message_contents(self):
        rv = self.send_message('a', 'a', 'a', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'message_contents' in response['message'].keys()
        assert response['message']['message_contents'] == "message_contents is either blank or incorrect type."

    def test_send_message_nonexistent_device_verify_key(self):
        rv = self.send_message('a', 'a', 'a', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Device does not exist."

    def test_send_message_unsigned_destination_usernames(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder), 'a', 'a', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_send_message_unsigned_message_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign('a')), 'a', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_send_message_unsigned_message_contents(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign('a')), b64encode(device_signing_key.sign('a')), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_send_message_invalid_message_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign('a')), b64encode(device_signing_key.sign('a')), b64encode(device_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Provided message_public_key is not a valid public key."

    def test_send_message_badsigned_destination_usernames(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(master_signing_key.sign('a')), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))), b64encode(device_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided username is corrupt or invalid."

    def test_send_message_badsigned_message_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign('a')), b64encode(master_signing_key.sign(public_key.encode(encoder=HexEncoder))), b64encode(device_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided message_public_key is corrupt or invalid."

    def test_send_message_badsigned_message_contents(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign('a')), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))), b64encode(master_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided message_contents is corrupt or invalid."

    def test_send_message_invalid_json_destination_usernames(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign('a')), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))), b64encode(device_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Provided destination_usernames must be JSON encapsulated."

    def test_send_message_invalid_list_destination_usernames(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign(json.dumps('a'))), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))), b64encode(device_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Provided destination_usernames must be a list."

    def test_send_message_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign(json.dumps([username]))), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))), b64encode(device_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 201
        assert response == device_signing_key.verify_key.encode(encoder=HexEncoder)

    def test_get_messages_empty_signed_device_verify_key(self):
        rv = self.get_messages(None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'signed_device_verify_key' in response['message'].keys()
        assert response['message']['signed_device_verify_key'] == "signed_device_verify_key is either blank or incorrect type."

    def test_get_messages_invalid_signed_device_verify_key(self):
        rv = self.get_messages('a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_get_messages_nonexistent_signed_device_verify_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(master_signing_key.sign(public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.get_messages(b64encode(device_signing_key.sign('a')))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Device does not exist."

    def test_get_messages_badsigned_signed_device_verify_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.get_messages(valid_device_verify_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided username is corrupt or invalid."

    def test_get_messages_valid_no_messages(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        rv = self.get_messages(b64encode(device_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 200
        assert 'messages' in response.keys()
        assert len(response['messages'].keys()) == 0

    def test_get_messages_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder), valid_device_public_key)
        self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign(json.dumps([username]))), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))), b64encode(device_signing_key.sign('a')))
        rv = self.get_messages(b64encode(device_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 200
        assert 'messages' in response.keys()
        assert len(response['messages'].keys()) == 1
        for key in response['messages'].keys():
            msg_keys = json.loads(response['messages'][key]).keys()
            assert 'reply_to' in msg_keys
            assert 'message_manifest' in msg_keys

if __name__ == '__main__':
    unittest.main()
