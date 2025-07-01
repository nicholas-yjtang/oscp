#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
project=$1
host_port=$2
source $SCRIPTDIR/network.sh
source $SCRIPTDIR/reverse_shell.sh
source $SCRIPTDIR/general.sh
start_listener
