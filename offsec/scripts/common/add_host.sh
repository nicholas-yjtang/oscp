#!/bin/bash
add_host() {
    host=$1
    ip=$2
    offsecwp_ip=$(cat /etc/hosts |  grep $host | awk '{print $1}')
    if [ -z "$offsecwp_ip" ]; then
        echo "$host not found in /etc/hosts, adding it now."
        echo "$ip $host" | sudo tee -a /etc/hosts
    else
        echo "$host already exists in /etc/hosts."
        echo "Updating $host IP address to $ip."
        sudo sed -i "s/.* $host/$ip $host/" /etc/hosts    
    fi
}

# check if script was sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    host=$1
    ip=$2
    if [[ -z "$host" ]] || [[ -z "$ip" ]]; then
        echo "Usage: $0 <HOST> <IP_ADDRESS>" 
        exit 1               
    else
        add_host "$host" "$ip"        
    fi     
fi