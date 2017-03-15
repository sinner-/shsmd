from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from base64 import b64encode
from shsmd.tests import common
import flask.wrappers
import json

class DeviceListTestCase(common.ShsmdTestCase):
    def test_fetch_device_empty_device_verify_key(self):
        rv = self.fetch_device(None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_fetch_device_empty_destination_username(self):
        rv = self.fetch_device('a', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'destination_username' in response['message'].keys()
        assert response['message']['destination_username'] == "destination_username is either blank or incorrect type."

    def test_fetch_device_nonexistent_device_verify_key(self):
        rv = self.fetch_device('a', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Device does not exist."

    def test_fetch_device_unsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        rv = self.fetch_device(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_fetch_device_unsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        rv = self.fetch_device(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_fetch_device_badsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        rv = self.fetch_device(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(master_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided username is corrupt or invalid."

    def test_fetch_device_nonexistent_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        rv = self.fetch_device(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 200
        assert 'device_verify_keys' in response.keys()
        assert len(response['device_verify_keys']) == 0

    def test_fetch_device_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        rv = self.fetch_device(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign(username.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 200
        assert 'device_verify_keys' in response.keys()
        assert response['device_verify_keys'][0] == device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8')

    def test_fetch_device_valid_multiple(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device1_signing_key = SigningKey.generate()
        device2_signing_key = SigningKey.generate()
        valid_device1_verify_key = b64encode(master_signing_key.sign(device1_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        valid_device2_verify_key = b64encode(master_signing_key.sign(device2_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device1_verify_key)
        self.register_device(username, valid_device2_verify_key)
        rv = self.fetch_device(device1_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device1_signing_key.sign(username.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 200
        assert 'device_verify_keys' in response.keys()
        assert device1_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8') in response['device_verify_keys']
        assert device2_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8') in response['device_verify_keys']

