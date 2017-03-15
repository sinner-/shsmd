from nacl.signing import SigningKey
from nacl.public import PrivateKey
from nacl.encoding import HexEncoder
from base64 import b64encode
from shsmd.tests import common
from shsmd.common import util
import flask.wrappers
import json

class KeyListTestCase(common.ShsmdTestCase):
    def test_fetch_key_empty_device_verify_key(self):
        rv = self.fetch_key(None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_fetch_key_empty_destination_username(self):
        rv = self.fetch_key('a', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'destination_username' in response['message'].keys()
        assert response['message']['destination_username'] == "destination_username is either blank or incorrect type."

    def test_fetch_key_nonexistent_device_verify_key(self):
        rv = self.fetch_key('a', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Device does not exist."

    def test_fetch_key_unsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        valid_device_public_key = b64encode(master_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.fetch_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_fetch_key_unsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.fetch_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_fetch_key_badsigned_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.fetch_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(master_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided username is corrupt or invalid."

    def test_fetch_key_nonexistent_destination_username(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key.encode(encoder=HexEncoder)
        valid_device_public_key = b64encode(device_signing_key.sign(public_key)).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.fetch_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 200
        assert len(response) == 0

    def test_fetch_key_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key.encode(encoder=HexEncoder)
        valid_device_public_key = b64encode(device_signing_key.sign(public_key)).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.fetch_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign(username.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 200
        assert util.reconstruct_signed_message(response[0]).message == public_key

    def test_fetch_key_valid_multiple(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device1_signing_key = SigningKey.generate()
        device2_signing_key = SigningKey.generate()
        valid_device1_verify_key = b64encode(master_signing_key.sign(device1_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        valid_device2_verify_key = b64encode(master_signing_key.sign(device2_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key1 = PrivateKey.generate().public_key.encode(encoder=HexEncoder)
        public_key2 = PrivateKey.generate().public_key.encode(encoder=HexEncoder)
        valid_device1_public_key = b64encode(device1_signing_key.sign(public_key1)).decode('utf-8')
        valid_device2_public_key = b64encode(device2_signing_key.sign(public_key2)).decode('utf-8')
        self.register_device(username, valid_device1_verify_key)
        self.register_device(username, valid_device2_verify_key)
        self.add_key(device1_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device1_public_key)
        self.add_key(device2_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device2_public_key)
        rv = self.fetch_key(device1_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device1_signing_key.sign(username.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 200
        assert valid_device1_public_key in response
        assert valid_device2_public_key in response
