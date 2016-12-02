# shsmd: Self Hosted Secure Messaging Daemon

[![Build Status](https://travis-ci.org/sinner-/shsmd.svg?branch=develop)](https://travis-ci.org/sinner-/shsmd)

## Overview

How hard is it to develop a secure, client-server style messaging system that supports multiple devices per user and multiple recipients per message?

This is my attempt to find out! 

This repository contains the server portion of the system against which many potential clients can be built (Desktop CLI, Desktop GUI, mobile, js). 

The design aims to retain as little data as possible:
  * Username
  * master verification key
  * device verification key
  * device public key
  * messages awaiting delivery
  * message recipients for messages awaiting delivery

No authentication is provided for API responses.
It is necessary to implement public access to the server through at least one of:
  * SSL terminator (e.g. nginx/haproxy), ECDH recommended
  * Tor Hidden Service
  * I2P eepsite

## Installation

### Install necessary OS packages:
  * Fedora:
    * `dnf install redhat-rpm-config python2-devel libffi-devel libsodium-devel mariadb-devel`

### Database setup
  * `CREATE DATABASE shsmd;`
  * `CREATE USER 'shsmd'@'%' IDENTIFIED by 'shsmd';`
  * `GRANT ALL ON shsmd.* TO 'shsmd'@'%';`
  
### Python setup
  * `git clone https://github.com/sinner-/shsmd`
  * `virtualenv -p /usr/bin/python2.7 shsmd`
  * `cd shsmd`
  * `source bin/activate`
  * `pip install -e .`

### Standalone daemon (development only)
  * (from inside shsmd directory)
  * `source bin/activate`
  * `shsmd`
    * NOTE: The database will be wiped on each run while debug=True in config.ini
