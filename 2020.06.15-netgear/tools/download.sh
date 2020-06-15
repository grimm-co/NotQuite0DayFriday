#!/bin/bash
netgear_page=$(mktemp)
urls=$(mktemp)
wget $1 -O $netgear_page 2> /dev/null

grep -io "http.*downloads.netgear.com/files/.*.zip" $netgear_page | grep -iv pdf | grep -iv ReadyShare | sort -u > $urls
aria2c --file-allocation=none -c -x 16 -s 16 -m 25 -j 10 -i $urls
rm -f $netgear_page $urls
