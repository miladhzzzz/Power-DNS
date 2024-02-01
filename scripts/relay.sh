#!/bin/bash

# Check if Docker is installed
if! command -v docker &> /dev/null
then
    echo "Docker is not installed. Installing it now..."
    sudo apt-get update
    sudo apt-get install -y docker.io
fi

# Build the Docker image
echo "Building docker image ...."
cd..
if! docker build -t power-dns:latest .
then
    echo "Failed to build Docker image. Aborting."
    exit 1
fi

# Run the Docker container
echo "Running power-dns Container ...."
if! docker run --name power-dns -p 8000:8000 -d power-dns:latest
then
    echo "Failed to run Docker container. Aborting."
    exit 1
fi

# Tell Argo to listen on localhost:8000
echo "Running Argo tunnel ..."
if! nohup cfd tunnel --url localhost:8000 --edge-ip-version auto --no-autoupdate -protocol http2 >> ~/dns.log &
then
    echo "Failed to start Argo tunnel. Aborting."
    exit 1
fi

# Wait for 5 seconds and cat the log file
echo "waiting for Tuneel URL ..."
sleep 5
cat ~/dns.log
