#!/bin/bash
ip=$2
ending_ip=$1
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
if [ -z "$ending_ip" ]; then
    echo "No ending IP provided. Please provide the ending IP as the first argument."
    exit 1
fi
if [ -z "$ip" ]; then
    partial_ip=$(cat partial_ip.txt 2>/dev/null)
    if [ -z "$partial_ip" ]; then
        partial_ip=$(cat $SCRIPTDIR/../../config/partial_ip.txt 2>/dev/null)
        if [ -z "$partial_ip" ]; then
            echo "No partial IP found. Please provide a valid partial IP in partial_ip.txt."
            exit 1
        else
            echo "Using partial IP from common directory"
        fi
    else
        echo "Using partial IP from current directory"
    fi
    ip="$partial_ip.$ending_ip"
    echo "Using IP: $ip"
fi
source $SCRIPTDIR/setup_range.sh
ip_parts=(${ip//./ })
subnet="${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}.0/24"
echo "Using subnet: $subnet"

source $SCRIPTDIR/urldecode.sh