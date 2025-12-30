#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

run_hydra_generic() {
    if [[ -z $1 ]]; then
        echo "Service not provided to run_hydra_generic"
        return 1
    fi
    local service="$1"
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP not provided, using default IP: $target_ip"
    fi
    if [[ -z $target_port ]]; then
        target_port=80
        echo "Target port not provided, using default port: $target_port"
    fi
    if [[ -z $username ]]; then
        username=usernames.txt
        echo "Username not provided, using default username list: $username"
    fi
    if [[ -z $password ]]; then
        password=passwords.txt
        echo "Password not provided, using default password list: $password"
    fi    
    local hydra_log="$log_dir/hydra_${service}_${target_ip}_${target_port}"
    if [[ ! -z $target_path ]]; then
        hydra_log+="${target_path}"
    fi
    hydra_log=$(echo "$hydra_log" | sed 's/\//_/g')
    hydra_log+=".log"
    if [[ -f $hydra_log ]]; then
        echo "Hydra log for $target_ip:$target_port already exists, skipping hydra"
        return 0
    fi
    local hydra_user_option=""
    if [[ -f $username ]]; then
        hydra_user_option="-L $username"
    else
        hydra_user_option="-l $username"
    fi
    local hydra_password_option=""
    if [[ -f $password ]]; then
        hydra_password_option="-P $password"
    else
        hydra_password_option="-p $password"
    fi
    echo hydra $hydra_user_option $hydra_password_option -f -V -o "$hydra_log" $service://$target_ip:$target_port${target_path}
    hydra $hydra_user_option $hydra_password_option -f -V -o "$hydra_log" $service://$target_ip:$target_port${target_path}

}

run_hydra_basic() {
    if [[ -z $target_port ]]; then
        target_port=80
        echo "Target port not provided, using default port: $target_port"
    fi
    run_hydra_generic "http-get"
}

run_hydra_ssh() {
    if [[ -z $target_port ]]; then
        target_port=22
        echo "Target port not provided, using default port: $target_port"
    fi
    run_hydra_generic "ssh"
}