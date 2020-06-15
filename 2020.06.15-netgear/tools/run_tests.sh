#!/bin/bash

# Clean up old tests and make the test directories
rm -rf /tmp/exploits1 /tmp/exploits2
mkdir /tmp/exploits1 /tmp/exploits2

# Restore the original version
cp exploit.py exploit_new.py
git checkout exploit.py
rm -f *.pyc

# Run the original version
python test.py /tmp/exploits1/ -file_only > /dev/null

# Put back the new version
mv exploit_new.py exploit.py
rm -f *.pyc

# Run the new version
python test.py /tmp/exploits2/ -file_only > /dev/null

# Compare the results
diff /tmp/exploits1/ /tmp/exploits2/
