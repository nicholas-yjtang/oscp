#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/ssh_utils.sh
username=$1
password=$2
ssh_target=$3
ssh_port=$4
trail_log=$5
if [[ -z "$username" || -z "$password" || -z "$ssh_target" ]]; then
    echo "Usage: $0 <username> <password> <ssh_target> <ssh_port> [trail_log]"
    exit 1
fi
run_ssh