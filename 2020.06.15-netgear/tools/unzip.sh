#!/bin/bash
for i in $(ls *.zip); do
	name=$(echo $i | cut -d- -f 2 | cut -d_ -f 1 | sed 's/V//g')
	#name=$(echo $i | cut -d_ -f 3 | sed 's/V//g')
	mkdir $name
	mv $i $name/
done
for i in $(ls); do
	pushd $i
	unzip *.zip
	popd
done
rm -f */*.html */*.htm
