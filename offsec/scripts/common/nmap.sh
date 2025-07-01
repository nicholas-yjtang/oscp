#!/bin/bash

nmap_tcp() {
    echo "Running TCP nmap scan..."
    if [[ -z "$ip" ]]; then
        echo "IP address and name must be set before running nmap."
        return 1
    fi
    if [[ -z "$nmap_tcp_log" ]]; then
        nmap_tcp_log="nmap_tcp.log"
    fi
    if [[ -f "$nmap_tcp_log" ]]; then
        echo "$nmap_tcp_log already exists, skipping nmap scan."
        return
    fi
    nmap -sC -sV -vv -oN $nmap_tcp_log $ip
    nmap -sVC -p- -v -T4 -sT --open $ip -oN $nmap_tcp_log
}

nmap_udp() {
    echo "Running UDP nmap scan..."
    if [[ -z "$ip" ]]; then
        echo "IP address and name must be set before running nmap."
        return 1
    fi

    if [[ -z "$nmap_udp_log" ]]; then
        nmap_udp_log="nmap_udp.log"
    fi
    if [[ -f "$nmap_udp_log" ]]; then
        echo "$nmap_udp_log already exists, skipping nmap scan."
        return
    fi
    sudo nmap -sU -sV -vv -oN $nmap_udp_log $ip
    sudo nmap -sU -p 1-1024 -v $ip -oN $nmap_udp_log
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