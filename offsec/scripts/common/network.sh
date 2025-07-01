#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

get_current_ip() {
    local current_ip=$(ip a | grep tun0 -A3 | grep "inet "| awk '{print $2}' | cut -d '/' -f 1)
    echo "$current_ip"
}

get_host_ip() {
    get_current_ip
}

port_in_use() {
    local port="$1"
    local result=$(netstat -tuln | grep ":${port} ") #listening ports
    if [[ -n "$result" ]]; then
        echo "true"
    else
        result=$(netstat -tuno | grep ":${port} ") #ports that have 
        if [[ -n "$result" ]]; then
            echo "true"
        else
            echo "false"
        fi
    fi
}

get_partial_ip () {
    echo $(cat $SCRIPTDIR/../../config/partial_ip.txt 2>/dev/null)
}