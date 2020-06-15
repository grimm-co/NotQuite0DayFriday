#!/bin/bash
model=$1
if [ "$model" = "" ]; then
	model=$(basename `pwd`)
	model=${model^^}
fi

for i in $(ls); do
	pushd $i
	binwalk -e *.chk
	popd
done

echo
echo

for i in $(find -type f -name httpd | sort -r); do
	md5=$(md5sum $i | cut -d\  -f 1)
	version=$(echo $i | cut -d/ -f 2)
	long_version=$(echo $i | grep -o 'V[0-9._NA]*\.chk')
	long_version=${long_version::-4}
	echo "#   $model       $long_version        $md5  Untested"
done

echo
echo

echo "\"$model\" : {"
for i in $(find -type f -name httpd | sort -r); do
	version=$(echo $i | cut -d/ -f 2)
	echo "\"$version\"     : 0x0,"
done
echo "},"

echo "\"$model\" : {"
for i in $(find -type f -name httpd | sort -r); do
	version=$(echo $i | cut -d/ -f 2)
	long_version=$(echo $i | grep -o 'V[0-9._]*\.chk')
	long_version=${long_version::-4}
	echo "\"$long_version\"     : \"$version\","
done
echo "},"

echo
echo
