#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/general.sh

run_gobuster() {
    echo "Running Gobuster..."
    local port=$1
    local target=$2
    local options=$3
    local target_protocol=$4
    if [[ -z "$target_protocol" ]]; then
        echo "Target protocol is not set, using default protocol http."
        target_protocol="http"
    fi
    if [[ -z "$target" ]]; then
        echo "Target is not set, using IP address."
        target=$ip
    fi
    if [[ -z "$port" ]]; then
        echo "Port is not set, using default port 80."
        port=80
    fi
    local gobuster_log="gobuster_$target""_$port"$options'.log'
    gobuster_log=$(echo "$gobuster_log" | sed -E 's/\ /_/g')
    echo "Using Gobuster log file: $gobuster_log"
    if [[ -d "$log_dir" ]]; then
        gobuster_log="$log_dir/$gobuster_log"
    fi        
    if [[ -f "$gobuster_log" ]]; then
        echo "$gobuster_log already exists, skipping Gobuster scan."
        return
    fi
    local proxy_options=""
    if [[ ! -z $use_proxychain ]] && [[ $use_proxychain == "true" ]]; then
          echo "Using proxychains for Gobuster scan."
          proxy_options="--proxy socks5://$proxy_target:$proxy_port"
    fi
    gobuster dir $proxy_options -u $target_protocol://$target:$port -w /usr/share/wordlists/dirb/common.txt $options --no-color --no-progress --quiet -o "$gobuster_log"

}

run_feroxbuster() {
    echo "Running Feroxbuster..."
    local port=$1
    local target=$2
    local target_protocol=$3
    if [[ -z "$target_protocol" ]]; then
        echo "Target protocol is not set, using default protocol http."
        target_protocol="http"
    fi
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
    
    local feroxbuster_log="feroxbuster_$target""_$port"
    if [[ ! -z "$feroxbuster_additional_options" ]]; then
        feroxbuster_log="${feroxbuster_log}_${feroxbuster_additional_options}"
        feroxbuster_log=$(echo "$feroxbuster_log" | sed -E 's/"//g' | sed -E 's/:/_/g' | sed -E 's/ /_/g')
        echo $feroxbuster_log
    fi
    feroxbuster_log="$feroxbuster_log.log"
    
    if [[ -d "$log_dir" ]]; then
        feroxbuster_log="$log_dir/$feroxbuster_log"

    fi  
    if [[ -f "$feroxbuster_log" ]]; then
        echo "$feroxbuster_log already exists, skipping Feroxbuster scan."
        return
    fi
    local proxy_options=""
    if [[ ! -z $use_proxychain ]] && [[ $use_proxychain == "true" ]]; then
          echo "Using proxychains for Gobuster scan."
          proxy_options="--proxy socks5://$proxy_target:$proxy_port"
    fi    
    eval feroxbuster -u "$target_protocol://$target""$target_port" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --quiet -x php,html,js,pdf,docx,json $feroxbuster_additional_options -o $feroxbuster_log $proxy_options
}

run_gobuster_vhost() {
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
    local gobuster_log="gobuster_vhost_$target""_$port"$options'.log'
    gobuster_log=$(echo "$gobuster_log" | sed -E 's/\ /_/g')
    echo "Using Gobuster log file: $gobuster_log"
    if [[ -d "$log_dir" ]]; then
        gobuster_log="$log_dir/$gobuster_log"
    fi        
    if [[ -f "$gobuster_log" ]]; then
        echo "$gobuster_log already exists, skipping Gobuster scan."
        return
    fi
    if [[ -z $gobuster_pattern_file ]]; then
        gobuster_pattern_file="gobuster_pattern"
    fi
    if [[ ! -f $gobuster_pattern_file ]]; then
        echo "{GOBUSTER}" > "$gobuster_pattern_file"
    fi
    gobuster vhost -u "http://$target:$port" -p "$gobuster_pattern_file" -w "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt" --no-color --no-progress --quiet -o "$gobuster_log"
}