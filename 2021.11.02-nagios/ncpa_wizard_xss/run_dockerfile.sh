#!/bin/bash

TAG=rogue_ncpa_container
docker build -t $TAG .

docker run --rm -it -p 0.0.0.0:5693:5693 $TAG
