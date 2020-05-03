#!/usr/bin/env python3

import os
import re
import struct
import json
import subprocess
import sys
import threading

import logging
logging.basicConfig(filename='/dev/null',level=logging.DEBUG)


# Helper function that sends a message to the webapp.
def send_message(message):
    # Write message size.
    sys.stdout.buffer.write(struct.pack('I', len(message)))
    logging.info('Sending '+message)
    # Write the message itself.
    sys.stdout.write(message)
    sys.stdout.flush()

def get_entries(pattern):
    try:
        res = subprocess.check_output('cat data/'+pattern, shell=True)
        return res.decode('latin-1').strip().split('\n')
    except Exception as e:
        logging.exception(str(e))
        return []

def get_password(pattern):
    entries = get_entries(pattern)

    match = None
    for entry in entries:
        match = re.search('username="(.*)",password="(.*)"', entry)
        if match is None:
            continue

        return {
            'type':'get_password_response',
            'pattern':pattern,
            'account':{
                'username':match.group(1),
                'password':match.group(2)
            }
        }

    return {'type':'get_password_response','pattern':pattern, 'account':None}

def get_sites():
    return {'type':'sites_response','sites':os.listdir('data')}

def store_entry(host, entry):
    host = host.replace('/','')
    with open(os.path.join('data',host), 'a') as f:
        f.write(entry+'\n')
    
def add_password(host, username, password):
    store_entry(host, 'username=%s,password=%s'%(
        json.dumps(username),
        json.dumps(password)))
    logging.info('Added new password for %s user %s'%(host, username))

def rpc_process(msg):
    if msg['type'] == 'add_password':
        add_password(msg['host'],msg['username'],msg['password'])
        return None
    if msg['type'] == 'add_entry':
        store_entry(msg['host'],msg['entry'])
        return None
    if msg['type'] == 'get_password':
        return get_password(msg['pattern'])
    if msg['type'] == 'sites':
        return get_sites()
    if msg['type'] == 'entries':
        return {
            'type':'entries_response',
            'pattern':msg['pattern'],
            'entries':get_entries(msg['pattern'])
        }
    if msg['type'] == 'ping':
        return { 'type':'pong' }

    return None

def read_loop():
    while 1:
        # Read the message length (first 4 bytes).
        text_length_bytes = sys.stdin.buffer.read(4)

        if len(text_length_bytes) == 0:
            break

        # Unpack message length as 4 byte integer.
        text_length = struct.unpack('i', text_length_bytes)[0]

        # Read the text (JSON object) of the message.
        text = sys.stdin.buffer.read(text_length).decode('utf-8')

        logging.info('got '+text)
        data = json.loads(text)

        if 'tabid' in data:
            resp = rpc_process(data['msg'])
            if resp is not None:
                send_message(json.dumps({'tabid':data['tabid'],'msg':resp}))
            continue

        #send_message('{"echo": %s}' % text)

def Main():
    if not os.path.exists('data'):
        os.makedirs('data')
    logging.info('Starting in '+os.getcwd())
    try:
        read_loop()
    except Exception as e:
        logging.exception(str(e))


if __name__ == '__main__':
    Main()
