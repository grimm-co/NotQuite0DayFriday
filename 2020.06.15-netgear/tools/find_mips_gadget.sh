#!/bin/bash
output_file=$1
binary=$2

IDA_PATH=~/idapro-7.3/idat

if [ "$output_file" = "" ]; then
  echo "Usage: find_mips_gadget.sh output_file [binary]"
  exit
fi

# Find the full path to the script
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
script=$SCRIPTPATH/find_mips_gadget.py
#script=$SCRIPTPATH/find_mips_gp_gadget.py

if [ "$binary" = "" ]; then
  temp_file=$(mktemp)
	rm -f $output_file

  for i in $(find -type f -name httpd | sort -r); do
    echo $i >> $output_file
    env OUTPUT_GADGET_NAME=$temp_file ~/idapro-7.3/idat -A -S$script -B $i
    cat $temp_file >> $output_file
    rm -f $temp_file
    echo >> $output_file
  done
else
  env OUTPUT_GADGET_NAME=$output_file ~/idapro-7.3/idat -A -S$script -B $binary
fi

