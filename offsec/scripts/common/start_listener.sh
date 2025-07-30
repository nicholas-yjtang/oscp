#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
project=$1
host_port=$2
interactive=$3
if [[ ! -z "$interactive" ]]; then
    echo "Starting listener in interactive mode..."
    interactive_shell=true
fi
source $SCRIPTDIR/network.sh
source $SCRIPTDIR/reverse_shell.sh
source $SCRIPTDIR/general.sh
start_listener
