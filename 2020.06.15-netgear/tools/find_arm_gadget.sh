#!/bin/bash
# This shell script uses grep to search through the output of objdump on ARM
# httpd binaries to find an appropriate gadget to ROP a call to system with a
# command on the stack. It looks for this gadget:
#
# mov r0, sp
# bl system
#
for i in $(find -name httpd -type f | sort); do
	echo $i ;
	objdump -d $i | grep "bl.*system" -B 1 | grep "mov.*r0, sp" -A 1;
	echo;
done
