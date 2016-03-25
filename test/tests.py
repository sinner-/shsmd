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
import shsmd

class ShsmdTestCase(unittest.TestCase):
    def setUp(self):
        self.db_fd, shsmd.app.config['DATABASE'] = tempfile.mkstemp()
        shsmd.app.config['TESTING'] = True
        self.app = shsmd.app.test_client()
        shsmd.db.init_db()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(shsmd.app.config['DATABASE'])

    def register_user(self, username, master_verify_key):
        return self.app.post('/api/v1.0/user',
                             data={'username': username,
                                   'master_verify_key': master_verify_key})

    def register_device(self, username, device_verify_key, device_public_key):
        return self.app.post('/api/v1.0/device',
                             data={'username': username,
                                   'device_verify_key': device_verify_key,
                                   'device_public_key': device_public_key})

    def fetch_key(self, device_verify_key, destination_username):
        return self.app.post('/api/v1.0/keylist',
                             data={'device_verify_key': device_verify_key,
                                   'destination_username': destination_username})

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
        rv = self.register_device(None, None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'username' in response['message'].keys()
        assert response['message']['username'] == "username is either blank or incorrect type."

    def test_register_device_empty_device_verify_key(self):
        rv = self.register_device('testuser', None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_register_device_empty_device_public_key(self):
        rv = self.register_device('testuser', 'a', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_public_key' in response['message'].keys()
        assert response['message']['device_public_key'] == "device_public_key is either blank or incorrect type."

    def test_register_device_nonexistent_username(self):
        rv = self.register_device('testuser', 'a', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Username does not exist."

    def test_register_device_unsigned_device_verify_key(self):
        username = 'testuser'
        master_verify_key = SigningKey.generate().verify_key.encode(encoder=HexEncoder)
        rv = self.register_user(username, master_verify_key)
        rv = self.register_device(username, 'a', 'a')
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
        rv = self.register_device(username, signed_invalid_device_verify_key, 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided device_verify_key is not valid."

    def test_register_device_unsigned_device_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        signed_valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        rv = self.register_device(username, signed_valid_device_verify_key, 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_register_device_invalid_device_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        signed_valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        signed_invalid_device_public_key = b64encode(master_signing_key.sign('a'))
        rv = self.register_device(username, signed_valid_device_verify_key, signed_invalid_device_public_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided device_public_key is not valid."

    def test_register_device_badsigned_device_verify_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        badsigned_device_verify_key = b64encode(device_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        signed_valid_device_public_key = b64encode(master_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        rv = self.register_device(username, badsigned_device_verify_key, signed_valid_device_public_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for device_verify_key is corrupt or invalid."

    def test_register_device_badsigned_device_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        badsigned_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        rv = self.register_device(username, valid_device_verify_key, badsigned_device_public_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for device_public_key is corrupt or invalid."

    def test_register_device_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder)))
        valid_device_public_key = b64encode(master_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        rv = self.register_device(username, valid_device_verify_key, valid_device_public_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 201
        assert response == device_signing_key.verify_key.encode(encoder=HexEncoder)

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
        self.register_device(username, valid_device_verify_key, valid_device_public_key)
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
        valid_device_public_key = b64encode(master_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key, valid_device_public_key)
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
        valid_device_public_key = b64encode(master_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder)))
        self.register_device(username, valid_device_verify_key, valid_device_public_key)
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
        valid_device_public_key = b64encode(master_signing_key.sign(public_key))
        self.register_device(username, valid_device_verify_key, valid_device_public_key)
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
        valid_device_public_key = b64encode(master_signing_key.sign(public_key))
        self.register_device(username, valid_device_verify_key, valid_device_public_key)
        rv = self.fetch_key(device_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device_signing_key.sign(username)))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 200
        assert 'device_public_keys' in response.keys()
        assert response['device_public_keys'][0] == public_key

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
        valid_device1_public_key = b64encode(master_signing_key.sign(public_key1))
        valid_device2_public_key = b64encode(master_signing_key.sign(public_key2))
        self.register_device(username, valid_device1_verify_key, valid_device1_public_key)
        self.register_device(username, valid_device2_verify_key, valid_device2_public_key)
        rv = self.fetch_key(device1_signing_key.verify_key.encode(encoder=HexEncoder), b64encode(device1_signing_key.sign(username)))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data)
        assert rv.status_code == 200
        assert 'device_public_keys' in response.keys()
        assert response['device_public_keys'][0] == public_key1
        assert response['device_public_keys'][1] == public_key2

if __name__ == '__main__':
    unittest.main()
