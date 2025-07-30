#!/bin/bash

nmap_tcp() {
    echo "Running TCP nmap scan..."
    target_ip=$1
    local additional_nmap_args=$2

    if [[ -z "$target_ip" ]]; then
        target_ip=$ip        
    fi
    echo "Target IP: $target_ip"
    if [[ -z "$target_ip" ]]; then
        echo "IP address must be set before running nmap."
        return 1
    fi
    local nmap_tcp_log="nmap_tcp_$target_ip.log"    
    if [[ ! -z "$additional_nmap_args" ]]; then
        nmap_tcp_log="${nmap_tcp_log%.log}_$additional_nmap_args.log"
    fi
    if [[ -d "$log_dir" ]]; then
        nmap_tcp_log="$log_dir/$nmap_tcp_log"
    fi
    if [[ -f "$nmap_tcp_log" ]]; then
        echo "$nmap_tcp_log already exists, skipping nmap scan."
        return
    fi
    nmap -sC -sV -vv $additional_nmap_args -oN $nmap_tcp_log $target_ip
    nmap -sVC -p- -v -T4 -sT --open $target_ip $additional_nmap_args -oN $nmap_tcp_log --append-output
}

configure_proxychains() {
    local proxy_target=$1
    if [[ -z "$proxy_target" ]]; then
        echo "Proxy target must be set."
        return 1
    fi
    local proxy_port=$2
    if [[ -z "$proxy_port" ]]; then
        proxy_port=4443  # Default proxy port
    fi

    configured=$(cat /etc/proxychains4.conf | grep socks5 | grep "$proxy_target" | grep "$proxy_port") 
    if [[ -z "$configured" ]]; then
        sudo sed -i -E '/^socks.*/d' /etc/proxychains4.conf
        sudo sed -i -E '/^http.*/d' /etc/proxychains4.conf
        echo "Configuring proxychains for $proxy_target:$proxy_port"
        echo "socks5 $proxy_target $proxy_port" | sudo tee -a /etc/proxychains4.conf > /dev/null
    else
        echo "Proxychains already configured for $proxy_target:$proxy_port"
    fi
}

nmap_tcp_proxychains() {
    local target_ip=$1
    if [[ -z "$target_ip" ]]; then
        echo "IP address must be set before running nmap."
        return 1
    fi
    local proxy_target=$2
    if [[ -z "$proxy_target" ]]; then
        proxy_target=$ip
    fi
    local proxy_port=$3
    if [[ -z "$proxy_port" ]]; then
        proxy_port=4443
    fi    
    configure_proxychains $2 $3

    local additional_nmap_args=$4    
    local nmap_tcp_log="nmap_tcp_$target_ip.log"
    if [[ ! -z "$additional_nmap_args" ]]; then
        nmap_tcp_log="${nmap_tcp_log%.log}_$additional_nmap_args.log"
    fi
    if [[ -d "$log_dir" ]]; then
        nmap_tcp_log="$log_dir/$nmap_tcp_log"
    fi
    if [[ -f "$nmap_tcp_log" ]]; then
        echo "$nmap_tcp_log already exists, skipping nmap scan."
        return
    fi
    proxy_available=$(nc -n -zv -w 1 $proxy_target $proxy_port 2>&1 | grep -c "open")
    if [[ "$proxy_available" -eq 0 ]]; then
        echo "Proxy at $proxy_target:$proxy_port is not available, please check your proxy is up."
        return 1
    fi
    echo "Running nmap with proxychains..."
    sudo proxychains nmap -v --open $additional_nmap_args -oN "$nmap_tcp_log" $target_ip
    #seq 1 65535 | xargs -P 50 -I port sudp proxychains -q nmap -sVC -p port -T4 -sT --open $target_ip $additional_nmap_args -oN $nmap_tcp_log --append-output

}

nmap_udp() {
    echo "Running UDP nmap scan..."
    target_ip=$1
    if [[ -z "$target_ip" ]]; then
        target_ip=$ip
    fi
    if [[ -z "$target_ip" ]]; then
        echo "IP address must be set before running nmap."
        return 1
    fi
    local nmap_udp_log="nmap_udp_$ip.log"    
    if [[ -d "$log_dir" ]]; then
        nmap_udp_log="$log_dir/$nmap_udp_log"
    fi

    if [[ -f "$nmap_udp_log" ]]; then
        echo "$nmap_udp_log already exists, skipping nmap scan."
        return
    fi
    sudo nmap -sU -sV -vv -oN $nmap_udp_log $target_ip
    sudo nmap -sU -p 1-1024 -v $target_ip -oN $nmap_udp_log --append-output
}

map_all() {
    nmap_tcp "$1" "$2"
    nmap_udp "$1" "$2"
}

autorecon_tcp() {
    echo "Running AutoRecon TCP scan..."
    if [[ -z "$ip" ]]; then
        echo "IP address and name must be set before running AutoRecon."
        return 1
    fi
    local autorecon_output=$project_name'_autorecon_tcp'
    if [[ -d "$autorecon_output" ]]; then
        echo "$autorecon_output already exists, skipping AutoRecon TCP scan."
        return
    fi
    autorecon -p T:1-65535 -o "$autorecon_output" $ip
}

autorecon_udp() {
    echo "Running AutoRecon UDP scan..."
    if [[ -z "$ip" ]]; then
        echo "IP address and name must be set before running AutoRecon."
        return 1
    fi
    local autorecon_output=$project_name"_autorecon_udp"
    if [[ -d "$autorecon_output" ]]; then
        echo "$autorecon_output already exists, skipping AutoRecon UDP scan."
        return
    fi
    autorecon -p U:1-1024 -o "$autorecon_output" $ip
}