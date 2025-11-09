#!/bin/bash
source ../setup.sh
source ./setup_network.sh
setup_network
stop_webdav_server
start_webdav_server
