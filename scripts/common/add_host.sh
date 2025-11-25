#!/bin/bash
add_host() {
    local host=$1
    local ip=$2
    if [[ -z $host ]]; then
        echo "Host name is required."
        exit 1
    fi
    if [[ -z $ip ]]; then
        echo "IP address is required."
        exit 1
    fi
    host=${host,,} # Convert to lowercase
    local test_host=$(echo "$host" | sed 's/\./\\\./g') # Escape dots
    local hostname_found=$(cat /etc/hosts |  grep -E " $test_host( |$)" | awk '{print $1}')
    local ip_found=$(cat /etc/hosts | grep $ip | awk '{print $1}')
    if [[ -z "$hostname_found" ]] && [[ -z "$ip_found" ]]; then
        echo "Adding $host with IP address $ip to /etc/hosts."
        echo "$ip $host" | sudo tee -a /etc/hosts
    fi
    if [[ -z "$hostname_found" ]] && [[ ! -z "$ip_found" ]]; then
        echo "IP address $ip already exists in /etc/hosts, updating $host."
        sudo sed -E -i 's/'$ip'(.*)/'$ip'\1 '$host'/' /etc/hosts
    fi
    if [[ ! -z "$hostname_found" ]] && [[ -z "$ip_found" ]]; then
        echo "Host $host already exists in /etc/hosts, updating IP address to $ip."
        sudo sed -E -i 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(.*) '$host'/'$ip'\1 '$host'/' /etc/hosts
    fi
    local final_check=$(cat /etc/hosts | grep -E " $test_host( |$)" | grep $ip)
    if [[ -z "$final_check" ]]; then
        echo "Host $host already exists in /etc/hosts, updating IP address to $ip."
        sudo sed -E -i 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(.*) '$host'/'$ip'\1 '$host'/' /etc/hosts
    else
        echo "$host with IP address $ip successfully added/updated in /etc/hosts."
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

