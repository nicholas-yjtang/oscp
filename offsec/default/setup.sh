#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
COMMONDIR=$(realpath "$SCRIPTDIR/scripts/common")
CURRENTDIR=$(pwd)
project=$CURRENTDIR
source $COMMONDIR/general.sh 
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
source $COMMONDIR/responder.sh
source $COMMONDIR/windows_escalate.sh
source $COMMONDIR/linux_escalate.sh
source $COMMONDIR/exploits.sh
source $COMMONDIR/pivot.sh
source $COMMONDIR/ad_tools.sh
source $COMMONDIR/offsec.sh
