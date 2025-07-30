#!/bin/bash
run_gobuster() {
    echo "Running Gobuster..."
    local port=$1
    local target=$2
    local options=$3
    if [[ -z "$target" ]]; then
        echo "Target is not set, using IP address."
        target=$ip
    fi
    if [[ -z "$port" ]]; then
        echo "Port is not set, using default port 80."
        port=80
    fi
    if [[ -z "$gobuster_log" ]]; then
        gobuster_log="gobuster_$target""_$port.log"
    fi
    if [[ -d "$log_dir" ]]; then
        gobuster_log="$log_dir/$gobuster_log"

    fi        
    if [[ -f "$gobuster_log" ]]; then
        echo "$gobuster_log already exists, skipping Gobuster scan."
        return
    fi
    gobuster dir -u http://$target:$port -w /usr/share/wordlists/dirb/common.txt $options --no-color --no-progress --quiet -o $gobuster_log

}

run_feroxbuster() {
    echo "Running Feroxbuster..."
    local port=$1
    local target=$2
    if [[ -z "$target" ]]; then
        echo "Target is not set, using IP address."
        target=$ip
    fi
    if [[ -z "$port" ]]; then
        echo "Port is not set, using default port 80."
        port=80
    else
        target_port=":$port"
    fi        
    if [[ -z "$feroxbuster_log" ]]; then
        feroxbuster_log="feroxbuster_$target""_$port.log"
    fi
    if [[ -d "$log_dir" ]]; then
        feroxbuster_log="$log_dir/$feroxbuster_log"

    fi  
    if [[ -f "$feroxbuster_log" ]]; then
        echo "$feroxbuster_log already exists, skipping Feroxbuster scan."
        return
    fi
    feroxbuster -u "http://$target""$target_port" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt --quiet --silent -o $feroxbuster_log 
}   