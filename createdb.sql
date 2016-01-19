DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS message_recipients;
CREATE TABLE users (username TEXT, master_verify_key TEXT);
CREATE TABLE devices (username TEXT, device_verify_key TEXT, device_public_key TEXT);
CREATE TABLE messages (message_id TEXT, message_contents TEXT, message_public_key TEXT);
CREATE TABLE message_recipients (device_verify_key TEXT, message_id TEXT);
