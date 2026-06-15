#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

rpc_enumerate() {
    local log_file=""
    if [[ -z $log_file ]]; then
        log_file="$log_dir/rpc_$target_ip.log"
    fi
    if [[ -f "$log_file" ]]; then
        echo "$log_file already exists, skipping RPC enumeration."
        return
    fi
    rpcinfo $ip | tee -a $log_file
    nmap -sSUC -p111 $ip | tee -a $log_file
}
