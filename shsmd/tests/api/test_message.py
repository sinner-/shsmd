from nacl.signing import SigningKey
from nacl.public import PrivateKey
from nacl.encoding import HexEncoder
from base64 import b64encode
from shsmd.tests import common
import flask.wrappers
import json

class MessageTestCase(common.ShsmdTestCase):
    def test_send_message_empty_device_verify_key(self):
        rv = self.send_message(None, None, None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'device_verify_key' in response['message'].keys()
        assert response['message']['device_verify_key'] == "device_verify_key is either blank or incorrect type."

    def test_send_message_empty_destination_usernames(self):
        rv = self.send_message('a', None, None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'destination_usernames' in response['message'].keys()
        assert response['message']['destination_usernames'] == "destination_usernames is either blank or incorrect type."

    def test_send_message_empty_message_public_key(self):
        rv = self.send_message('a', 'a', None, None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'message_public_key' in response['message'].keys()
        assert response['message']['message_public_key'] == "message_public_key is either blank or incorrect type."

    def test_send_message_empty_message_contents(self):
        rv = self.send_message('a', 'a', 'a', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'message_contents' in response['message'].keys()
        assert response['message']['message_contents'] == "message_contents is either blank or incorrect type."

    def test_send_message_nonexistent_device_verify_key(self):
        rv = self.send_message('a', 'a', 'a', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "Device does not exist."

    def test_send_message_unsigned_destination_usernames(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), 'a', 'a', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_send_message_unsigned_message_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'), 'a', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_send_message_unsigned_message_contents(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'), 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided signed_message is not valid."

    def test_send_message_invalid_message_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        valid_device_public_key = b64encode(device_signing_key.sign(PrivateKey.generate().public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Provided message_public_key is not a valid public key."

    def test_send_message_badsigned_destination_usernames(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(master_signing_key.sign('a'.encode())).decode('utf-8'), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided username is corrupt or invalid."

    def test_send_message_badsigned_message_public_key(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'), b64encode(master_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided message_public_key is corrupt or invalid."

    def test_send_message_badsigned_message_contents(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8'), b64encode(master_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Signature for provided message_contents is corrupt or invalid."

    def test_send_message_invalid_json_destination_usernames(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Provided destination_usernames must be JSON encapsulated."

    def test_send_message_invalid_list_destination_usernames(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign(json.dumps('a').encode())).decode('utf-8'), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "Provided destination_usernames must be a list."

    def test_send_message_valid(self):
        username = 'testuser'
        master_signing_key = SigningKey.generate()
        self.register_user(username, master_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'))
        device_signing_key = SigningKey.generate()
        valid_device_verify_key = b64encode(master_signing_key.sign(device_signing_key.verify_key.encode(encoder=HexEncoder))).decode('utf-8')
        public_key = PrivateKey.generate().public_key
        valid_device_public_key = b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8')
        self.register_device(username, valid_device_verify_key)
        self.add_key(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), valid_device_public_key)
        rv = self.send_message(device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8'), b64encode(device_signing_key.sign(json.dumps([username]).encode())).decode('utf-8'), b64encode(device_signing_key.sign(public_key.encode(encoder=HexEncoder))).decode('utf-8'), b64encode(device_signing_key.sign('a'.encode())).decode('utf-8'))
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 201
        assert response == device_signing_key.verify_key.encode(encoder=HexEncoder).decode('utf-8')

