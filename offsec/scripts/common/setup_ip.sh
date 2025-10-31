#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source "$SCRIPTDIR/setup_range.sh"

perform_full_setup() {
    setup_partial_ip    
    setup_range
    setup_subnet
    echo "ip: $ip"
}

input=$1
if [[ -z "$input" ]]; then
    echo "Warning! No argument provided. Please provide ending ip or ip address"
    input=1
    echo "Going to use a temporary value of $input"
fi

if [[ "$input" =~ ^[0-9]+$ ]]; then
    ending_ip="$input"
else
    if [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip="$input"
    else
        echo "Warning! Invalid argument. Please provide a valid IP address or ending octet."
        return 1
    fi
fi
perform_full_setup