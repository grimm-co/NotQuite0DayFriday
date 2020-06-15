#!/bin/bash
for i in $(find -type f -name httpd | sort -r); do
	md5sum `pwd`/$i;
done
