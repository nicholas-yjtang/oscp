#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source "$SCRIPTDIR/setup_range.sh"

perform_full_setup() {
    setup_partial_ip    
    setup_range
    setup_subnet
    echo "ip: $ip"
}

if [[ -z "$1" ]]; then
    echo "Warning! No argument provided. Please provide ending ip or ip address"
    echo "Your variable ip might not be set correctly."
    return 1
fi

if [[ "$1" =~ ^[0-9]+$ ]]; then
    ending_ip="$1"
else
    if [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip="$1"
    else
        echo "Warning! Invalid argument. Please provide a valid IP address or ending octet."
        return 1
    fi
fi
perform_full_setup