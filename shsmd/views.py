""" shsmd
"""

from shsmd import api
from shsmd.user import User
from shsmd.device import Device
from shsmd.key import Key
from shsmd.keylist import KeyList
from shsmd.message import Message
from shsmd.messagelist import MessageList

api.add_resource(User, '/api/v1.0/user')
api.add_resource(Device, '/api/v1.0/device')
api.add_resource(Key, '/api/v1.0/key')
api.add_resource(KeyList, '/api/v1.0/keylist')
api.add_resource(Message, '/api/v1.0/message')
api.add_resource(MessageList, '/api/v1.0/messagelist')
