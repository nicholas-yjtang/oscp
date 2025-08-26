#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/urldecode.sh

get_current_ip() {
    local current_ip=""
    current_ip=$(ip a | grep tun0 -A3 | grep "inet "| awk '{print $2}' | cut -d '/' -f 1)
    echo "$current_ip"
}

get_host_ip() {
    host_ip=$(get_current_ip)
    echo "$host_ip"
}

port_in_use() {
    local port="$1"
    local result=""
    result=$(netstat -tuln | grep ":${port} ") #listening ports
    if [[ -n "$result" ]]; then
        echo "true"
        return 0
    else
        result=$(netstat -tuno | grep ":${port} ") #ports that have 
        if [[ -n "$result" ]]; then
            echo "true"
            return 0
        else
            echo "false"
            return 1
        fi        
    fi
}


get_partial_ip () {
    if [[ -z "$partial_ip" ]]; then
        partial_ip=$(cat $SCRIPTDIR/../../config/partial_ip.txt 2>/dev/null)
    fi
    echo "$partial_ip"
}

get_third_octet() {
    if [[ ! -z "$third_octet" ]]; then
        echo "$third_octet"
        return 0
    fi
    if [[ -z "$partial_ip" ]]; then
        partial_ip=$(get_partial_ip)
    fi
    if [[ -z "$partial_ip" ]]; then
        echo "Partial IP is not set. Please set it using change_partial_ip.sh."
        exit 1
    fi
    third_octet=$(echo "$partial_ip" | cut -d '.' -f 3)
    echo "$third_octet"
}

run_tcpdump() {

    if [ -z "$tcpdump_log" ]; then
        tcpdump_log="tcpdump.log"
    fi
    local port=$1
    if [ ! -z "$port" ]; then
        port="port $port"
    fi
    echo "Running tcpdump...$tcpdump_log"
    tcpdump_running=$(ps aux | grep tcpdump | grep -v grep)
    if [ -z "$tcpdump_running" ]; then
        echo "Starting tcpdump..."
        sudo tcpdump -i tun0 -A $port > "$tcpdump_log" &
    else
        echo "tcpdump is already running, skipping."
    fi
}

stop_tcpdump() {
    echo "Stopping tcpdump..."
    local tcpdump_pid=""
    tcpdump_pid=$(pgrep -f "tcpdump -i tun0")
    if pgrep -f "tcpdump -i tun0"; then
        for pid in $tcpdump_pid; do
            sudo kill -9 "$pid"
        done
        echo "tcpdump stopped."
    else
        echo "No tcpdump process found."
    fi
}