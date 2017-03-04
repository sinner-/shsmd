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
    * `dnf install redhat-rpm-config python2-devel libffi-devel libsodium-devel mariadb-devel mariadb-server python-pip python-virtualenvwrapper`

### Database setup
  * `CREATE DATABASE shsmd;`
  * `CREATE USER 'shsmd'@'%' IDENTIFIED by 'shsmd';`
  * `GRANT ALL ON shsmd.* TO 'shsmd'@'%';`
  
### Setup
  * `git clone https://github.com/sinner-/shsmd`
  * `cd shsmd`
  * `source /usr/bin/virtualenvwrapper.sh`
  * `mkvirtualenv shsmd`
  * `python setup.py install`
  * `shsmd-manage --initschema`

### Standalone daemon
  * `workon shsmd` (if not already in virtualenv created during setup
  * `shsmd-api` (optionally run `shsmd-manage --dropschema --initschema` first)
