from nacl.signing import SigningKey
from nacl.public import PrivateKey
from nacl.encoding import HexEncoder
from base64 import b64encode
from shsmd.tests import common
import flask.wrappers
import json

class MessageTestCase(common.ShsmdTestCase):
    def test_get_messages_empty_signed_device_verify_key(self):
        rv = self.get_messages(None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_get_messages_invalid_signed_device_verify_key(self):
        rv = self.get_messages('a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_get_messages_nonexistent_signed_device_verify_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(master_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.get_messages(b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Device does not exist."

    def test_get_messages_badsigned_signed_device_verify_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.get_messages(valid_device_verify_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided username is corrupt or invalid."

    def test_get_messages_valid_no_messages(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.get_messages(b64encode(device_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 200
        assert len(response.keys()) == 0

    def test_get_messages_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign(json.dumps([username]).encode())).decode('utf-8'), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'))
        rv = self.get_messages(b64encode(device_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 200
        assert len(response.keys()) == 1
        for key in response.keys():
            msg_keys = json.loads(response[key]).keys()
            assert 'reply_to' in msg_keys
            assert 'message_manifest' in msg_keys
        rv = self.get_messages(b64encode(device_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8'))
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 200
        assert len(response.keys()) == 0
