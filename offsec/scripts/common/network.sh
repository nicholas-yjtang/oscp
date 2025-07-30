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

get_third_octet() {
    local partial_ip=$(get_partial_ip)
    if [[ -z "$partial_ip" ]]; then
        echo "Partial IP not set. Please set it using change_partial_ip.sh."
        exit 1
    fi
    local third_octet=$(echo $partial_ip | cut -d '.' -f 3)
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
    local tcpdump_pid=$(pgrep -f "tcpdump -i tun0")
    if [ -n "$tcpdump_pid" ]; then
        for pid in $tcpdump_pid; do
            sudo kill -9 $pid
        done
        echo "tcpdump stopped."
    else
        echo "No tcpdump process found."
    fi
}