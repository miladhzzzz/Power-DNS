#!/bin/bash

# we want to run the dns server as a relay on a remote host using docker and argo

# to start the process we first build the docker image

cd ..

docker build -t power-dns:latest .

# next we need to run the container

docker run --name power-dns -p -d 8000:8000 5335:5335 power-dns:latest

# then we need to tell argo to start listening on localhost:8000

nohup cfd tunnel --url localhost:8000 --edge-ip-version auto --no-autoupdate -protocol http2 >>dns.log &

# then we wait 5 seconds and cat the dns.log and exit
sleep 5

cat dns.log
