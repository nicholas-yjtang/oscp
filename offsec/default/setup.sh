#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
COMMONDIR=$(realpath "$SCRIPTDIR/../scripts/common")
project_name=$2
source $COMMONDIR/setup_ip.sh $1
source $COMMONDIR/traverse.sh
source $COMMONDIR/add_host.sh
source $COMMONDIR/network.sh
source $COMMONDIR/nmap.sh
source $COMMONDIR/searchsploit.sh
source $COMMONDIR/gobuster.sh
source $COMMONDIR/xfreerdp.sh
source $COMMONDIR/ssh_utils.sh
source $COMMONDIR/http_server.sh
source $COMMONDIR/reverse_shell.sh