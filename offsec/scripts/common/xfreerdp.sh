#!/bin/bash


run_xfreerdp() {
    if [ -z  "$username" ] || [ -z "$password" ]; then
        echo "username and password must be set before running xfreerdp."
        return 1
    fi
    local port=$1
    if [ -z "$port" ]; then
        port=3389  # Default RDP port
    fi
    domain_option=""
    if [ ! -z "$domain" ]; then
        domain_option="/d:$domain"
    fi
    if [ -z "$rdp_ip" ]; then
        rdp_ip=$ip
    fi
    if [ -z "$trail_log" ]; then
        trail_log="trail.log"
    fi
    xfreerdp /v:"$rdp_ip" /port:$port $domain_option /u:$username /p:$password /cert-ignore /smart-sizing +home-drive +clipboard  >> $trail_log 2>&1
}