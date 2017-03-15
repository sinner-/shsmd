from nacl.signing import SigningKey
from nacl.public import PrivateKey
from nacl.encoding import HexEncoder
from shsmd.tests import common
from base64 import b64encode
import flask.wrappers
import json

class KeyTestCase(common.ShsmdTestCase):
    def test_add_key_empty_device_verify_key(self):
        rv = self.add_key(None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_add_key_empty_device_public_key(self):
        rv = self.add_key('a', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_public_key' in response['message'].keys()
        assert response['message']['device_public_key'] == "device_public_key is either blank or incorrect type."

    def test_add_key_nonexistent_device(self):
        rv = self.add_key('a','a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Device does not exist."

    def test_add_key_unsigned_device_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        rv = self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_add_key_invalid_device_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        rv = self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided device_public_key is not valid."

    def test_add_key_badsigned_device_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        rv = self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'),
                          b64encode(master_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder))).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for device_public_key is corrupt or invalid."

    def test_add_key_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        rv = self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'),
                          b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder))).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 201

