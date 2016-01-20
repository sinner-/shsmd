DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS message_recipients;
CREATE TABLE users (
    username TEXT PRIMARY KEY NOT NULL,
    master_verify_key TEXT NOT NULL);
CREATE TABLE devices (
    device_verify_key TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL,
    device_public_key TEXT NOT NULL,
    FOREIGN KEY(username) REFERENCES users(username));
CREATE TABLE messages (
    message_id TEXT PRIMARY KEY NOT NULL,
    message_contents TEXT NOT NULL,
    message_public_key TEXT NOT NULL);
CREATE TABLE message_recipients (
    device_verify_key TEXT PRIMARY KEY NOT NULL,
    message_id TEXT NOT NULL,
    FOREIGN KEY(message_id) REFERENCES messages(message_id));
