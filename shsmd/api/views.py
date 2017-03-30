from shsmd.api import api
from shsmd.api.user import User
from shsmd.api.device import Device
from shsmd.api.devicelist import DeviceList
from shsmd.api.key import Key
from shsmd.api.keylist import KeyList
from shsmd.api.message import Message
from shsmd.api.messagelist import MessageList

api.add_resource(User, '/api/v1.0/users/<username>')
api.add_resource(Device, '/api/v1.0/users/<username>/devices/<device_id>')
api.add_resource(DeviceList, '/api/v1.0/users/<username>/devices')
api.add_resource(Key, '/api/v1.0/users/<username>/keys/<key_id>')
api.add_resource(KeyList, '/api/v1.0/users/<username>/keys')
api.add_resource(Message, '/api/v1.0/message')
api.add_resource(MessageList, '/api/v1.0/users/<username>/devices/<device_id>/messages')
