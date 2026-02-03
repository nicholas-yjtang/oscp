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
    local target_option=""
    if [[ ! -z $target_url ]] && [[ -z $1 ]]; then
        target_option="-u $target_url"
    else
        target_option="-u $target_protocol://$target:$port"
        target_url="$target_protocol://$target:$port"
    fi
    if [[ -z $gobuster_wordlist ]]; then
        gobuster_wordlist="/usr/share/wordlists/dirb/common.txt"
    fi
    if [[ ! -f $gobuster_wordlist ]]; then
        echo "Gobuster wordlist $gobuster_wordlist does not exist. Exiting."
        return 1
    fi
    local authentication_options=""
    if [[ -z $username ]] && [[ -z $password ]]; then
        echo "No authentication credentials provided for Gobuster."
    else
        authentication_options="-U $username -P $password"
        echo "Using authentication credentials for Gobuster."
        options+=" $authentication_options"
    fi
    local gobuster_log="gobuster_${target_url}${options}.log"
    gobuster_log=$(echo "$gobuster_log" | sed -E 's/\ /_/g' | sed -E 's/:/_/g' | sed -E 's/\//_/g' | sed -E 's/"//g' | sed -E "s/'//g")
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
    if [[ -z $gobuster_extensions ]]; then
        gobuster_extensions="pdf,txt,php,html,docx,jsp,aspx,js,zip"
    fi
    local gobuster_cmd="gobuster dir $proxy_options $target_option -w $gobuster_wordlist -x $gobuster_extensions $options --no-color --no-progress --quiet -o \"$gobuster_log\""
    echo "$gobuster_cmd" | tee -a $trail_log
    eval "$gobuster_cmd"
    gobuster_cmd="gobuster dir $proxy_options $target_option -w $gobuster_wordlist -f $options --no-color --no-progress --quiet"
    echo "$gobuster_cmd" | tee -a $trail_log
    eval "$gobuster_cmd" | tee >(remove_color_to_log "$gobuster_log")

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
    local feroxbuster_target_url=""
    if [[ ! -z $target_url ]] && [[ -z $1 ]] ; then
        feroxbuster_target_url="$target_url"

    else
        feroxbuster_target_url="$target_protocol://$target$target_port"
    fi
    if [[ ! -z $username ]] && [[ ! -z $password ]]; then
        feroxbuster_additional_options+=" -H 'Authorization: Basic $(echo -n "$username:$password" | base64 -w 0)' "
        echo "Using authentication credentials for Feroxbuster."
    fi
    #-x php,html,js,pdf,docx,json,txt
    if [[ ! -z $feroxbuster_file_extensions ]]; then
        feroxbuster_additional_options+=" -x $feroxbuster_file_extensions"
    fi

    local feroxbuster_log="feroxbuster_$feroxbuster_target_url"
    if [[ ! -z "$feroxbuster_additional_options" ]]; then
        feroxbuster_log="${feroxbuster_log}_${feroxbuster_additional_options}"
        #feroxbuster_log=$(echo "$feroxbuster_log" | sed -E 's/"//g' | sed -E 's/:/_/g' | sed -E 's/ /_/g')
        #echo $feroxbuster_log
    fi
    feroxbuster_log=$(echo "$feroxbuster_log" | sed -E 's/:/_/g' | sed -E 's/\//_/g' | sed -E 's/"//g' | sed -E 's/ /_/g' | sed -E "s/'//g")
    feroxbuster_log="$feroxbuster_log.log"
    echo "Using Feroxbuster log file: $feroxbuster_log"
    
    if [[ -d "$log_dir" ]]; then
        feroxbuster_log="$log_dir/$feroxbuster_log"

    fi  
    if [[ -f "$feroxbuster_log" ]]; then
        echo "$feroxbuster_log already exists, skipping Feroxbuster scan."
        return
    fi
    if [[ -z $feroxbuster_wordlist ]]; then
        feroxbuster_wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    fi
    local proxy_options=""
    if [[ ! -z $use_proxychain ]] && [[ $use_proxychain == "true" ]]; then
          echo "Using proxychains for Gobuster scan."
          proxy_options="--proxy socks5://$proxy_target:$proxy_port"
    fi   
    local cmd_string="feroxbuster -u $feroxbuster_target_url -w $feroxbuster_wordlist --quiet $feroxbuster_additional_options -o $feroxbuster_log $proxy_options"
    echo "Feroxbuster command: $cmd_string" | tee -a $trail_log
    eval "$cmd_string"
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