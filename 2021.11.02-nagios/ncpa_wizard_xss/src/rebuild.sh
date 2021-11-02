#!/bin/bash

set -ex

sudo ./build.sh 

sudo /etc/init.d/ncpa_listener stop

sudo cp -r ncpa/* /usr/local/ncpa/

sudo /etc/init.d/ncpa_listener start

sudo netstat -plant

