DROP TABLE IF EXISTS message_recipients;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS pubkeys;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    username VARCHAR(65) PRIMARY KEY NOT NULL,
    master_verify_key VARCHAR(65) NOT NULL);
CREATE TABLE devices (
    device_verify_key VARCHAR(65) PRIMARY KEY NOT NULL,
    username VARCHAR(65) NOT NULL,
    FOREIGN KEY(username) REFERENCES users(username));
CREATE TABLE pubkeys (
    device_public_key VARCHAR(173) PRIMARY KEY NOT NULL,
    device_verify_key VARCHAR(65) NOT NULL,
    FOREIGN KEY(device_verify_key) REFERENCES devices(device_verify_key));
CREATE TABLE messages (
    message_id VARCHAR(90) PRIMARY KEY NOT NULL,
    reply_to VARCHAR(65) NOT NULL,
    message_contents LONGTEXT NOT NULL,
    message_public_key VARCHAR(173) NOT NULL,
    FOREIGN KEY (reply_to) REFERENCES users(username));
CREATE TABLE message_recipients (
    device_verify_key VARCHAR(65) NOT NULL,
    message_id VARCHAR(90) NOT NULL,
    FOREIGN KEY(message_id) REFERENCES messages(message_id));
CREATE INDEX users_username ON users (username);
CREATE INDEX devices_username ON devices (username);
CREATE INDEX devices_verify_key ON devices (device_verify_key);
