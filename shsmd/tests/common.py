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
