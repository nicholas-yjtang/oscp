#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/setup_ip.sh 152 $1
xfreerdp /v:$ip:3389 /u:student /p:lab /size:2048x1536 /scale-desktop:200 +clipboard