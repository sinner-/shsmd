from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from shsmd.tests import common
import flask.wrappers
import json

class UserTestCase(common.ShsmdTestCase):

    def test_register_user_empty_key(self):
        rv = self.register_user('testuser', None)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert 'master_verify_key' in response['message'].keys()
        assert response['message']['master_verify_key'] == "master_verify_key is either blank or incorrect type."

    def test_register_user_invalid_master_verify_key(self):
        rv = self.register_user('testuser', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 400
        assert 'message' in response.keys()
        assert response['message'] == "The provided master_verify_key is not valid."

    def test_register_user_valid(self):
        username = 'testuser'
        test_key = SigningKey.generate().verify_key.encode(encoder=HexEncoder).decode('utf-8')
        rv = self.register_user(username, test_key)
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 201
        assert response == "User %s registered successfully." % username

    def test_register_user_existing_username(self):
        test_key = SigningKey.generate().verify_key.encode(encoder=HexEncoder).decode('utf-8')
        self.register_user('testuser', test_key)
        rv = self.register_user('testuser', 'a')
        assert isinstance(rv, flask.wrappers.Response)
        response = json.loads(rv.data.decode('utf-8'))
        assert rv.status_code == 422
        assert 'message' in response.keys()
        assert response['message'] == "username already registered."
