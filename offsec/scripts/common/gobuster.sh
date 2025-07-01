#!/bin/bash
run_gobuster() {
    echo "Running Gobuster..."
    if [[ -z "$ip" ]]; then
        echo "IP address is not set."
        return 1
    fi
    local port=$1
    local name=$2
    local hostname=$3
    if [[ -z "$gobuster_log" ]]; then
        gobuster_log="gobuster.log"
    fi
    if [[ -f "$gobuster_log" ]]; then
        echo "$gobuster_log already exists, skipping Gobuster scan."
        return
    fi    
    if [[ ! -z "$hostname" ]]; then
        gobuster dir -u http://$hostname:$port -w /usr/share/wordlists/dirb/common.txt -o $gobuster_log 
    else
        gobuster dir -u http://$ip:$port -w /usr/share/wordlists/dirb/common.txt -o $gobuster_log 
    fi
}