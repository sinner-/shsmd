import os
import unittest
import tempfile
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
        return self.app.put('/api/v1.0/users/%s' % username,
                            data={'master_verify_key': master_verify_key})

    def register_device(self, username, device_id, device_verify_key):
        return self.app.put('/api/v1.0/users/%s/devices/%s' % (username, device_id),
                            data={'device_verify_key': device_verify_key})

    def add_key(self, username, key_id, device_verify_key, device_public_key):
        if device_verify_key is None:
            headers = {}
        else:
            headers = {'device-verify-key': device_verify_key}
        return self.app.put('/api/v1.0/users/%s/keys/%s' % (username, key_id),
                            headers=headers,
                            data={'device_public_key': device_public_key})

    def fetch_key(self, device_verify_key, username):
        if device_verify_key is None:
            headers = {}
        else:
            headers = {'device-verify-key': device_verify_key}
        return self.app.get('/api/v1.0/users/%s/keys' % username,
                            headers=headers)

    def fetch_device(self, device_verify_key, username):
        if device_verify_key is None:
            headers = {}
        else:
            headers = {'device-verify-key': device_verify_key}
        return self.app.get('/api/v1.0/users/%s/devices' % username,
                            headers=headers)

    def send_message(self, device_verify_key, destination_usernames, message_public_key, message_contents):
        return self.app.post('/api/v1.0/message',
                             data={'device_verify_key': device_verify_key,
                                   'destination_usernames': destination_usernames,
                                   'message_public_key': message_public_key,
                                   'message_contents': message_contents})

    def get_messages(self, username, device_id, device_verify_key):
        if device_verify_key is None:
            headers = {}
        else:
            headers = {'device-verify-key': device_verify_key}
        return self.app.get('/api/v1.0/users/%s/devices/%s/messages' % (username, device_id),
                             headers=headers)
