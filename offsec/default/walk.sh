#!/bin/bash
source ./setup.sh 214
echo $COMMONDIR/start_listener.sh $project 4444
nmap_tcp
stop_webdav_server
start_webdav_server