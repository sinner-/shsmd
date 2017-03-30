from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from base64 import b64encode
from shsmd.tests import common
import flask.wrappers
import json

class DeviceTestCase(common.ShsmdTestCase):

    def test_register_device_empty_device_verify_key(self):
        rv = self.register_device('testuser', None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_register_device_unsigned_device_verify_key(self):
        username = 'testuser'
        master_verify_key = SigningKey.generate().verify_key.encode(encoder=HexEncoder).decode('utf-8')
        rv = self.register_user(username, master_verify_key)
        rv = self.register_device(username, 'a', 'a',)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_register_device_invalid_device_verify_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder))
        signed_invalid_device_verify_key = b64encode(master_signing_key.sign('a'.encode())).decode('utf-8')
        rv = self.register_device(username, 'a', signed_invalid_device_verify_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided device_verify_key is not valid."

    def test_register_device_badsigned_device_verify_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        rv = self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        badsigned_device_verify_key = b64encode(device_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        rv = self.register_device(username, device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), badsigned_device_verify_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for device_verify_key is corrupt or invalid."

    def test_register_device_mismatched_device_id(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        rv = self.register_device(username, 'a', valid_device_verify_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The device_verify_key does not match supplied device ID."

    def test_register_device_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        rv = self.register_device(username, device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_verify_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 201
        assert response == "Device %s registered successfully." % device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8')
