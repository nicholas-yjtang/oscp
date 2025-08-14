#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

setup_range() {
    if [ -z "$ip" ]; then
        echo "No IP provided."
        exit 1
    fi
    IFS="." read -ra ip_parts <<< "$ip"
    ip_range="${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}.1-253"
    echo "ip_range: $ip_range"
}

setup_partial_ip() {
    if [ ! -z "$ip" ]; then
        echo "IP has been provided: $ip"
        ip_parts=(${ip//./ })
        partial_ip="${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}"
    else 
        if [ -z "$ending_ip" ]; then
            echo "No ending IP provided. Please provide a valid ending octet or full IP address."
            exit 1
        fi
        partial_ip=$(cat partial_ip.txt 2>/dev/null)
        if [ -z "$partial_ip" ]; then
            partial_ip=$(cat "$SCRIPTDIR/../../config/partial_ip.txt" 2>/dev/null)
            if [ -z "$partial_ip" ]; then
                echo "No partial IP found. Please provide a valid partial IP in partial_ip.txt."
                exit 1
            else
                echo "Using partial IP from common directory"
            fi
        else
            echo "Using partial IP from current directory"
        fi
        ip="${partial_ip}.$ending_ip"
    fi
}

setup_subnet() {
    if [[ -z "$partial_ip" ]]; then
        echo "Partial IP not set. Please set it using change_partial_ip.sh."
        exit 1
    fi
    subnet="$partial_ip.0/24"
    echo "subnet: $subnet"
}