#!/bin/bash
source ../setup.sh 214
source ./setup_network.sh
echo $COMMONDIR/start_listener.sh $project 4444
setup_network
nmap_tcp
stop_webdav_server
start_webdav_server