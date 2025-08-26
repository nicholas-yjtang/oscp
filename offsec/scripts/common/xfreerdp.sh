#!/bin/bash


run_xfreerdp() {
    if [ -z  "$username" ]; then
        echo "username must be set before running xfreerdp."
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
    if [[ ! -z $run_rdp_forced ]] && [[ $run_rdp_forced == "true" ]]; then
        echo "Running xfreerdp with forced RDP connection"
    else
        local rdp_running=$(ss -tupn | grep "$rdp_ip:$port")
        if [ ! -z "$rdp_running" ]; then
            echo "RDP is already running on $rdp_ip:$port"
            return
        fi
    fi

    echo "Starting xfreerdp to connect to $rdp_ip on port $port with username $username"
    local xfreerdp_options="/v:$rdp_ip /port:$port $domain_option /u:$username /cert-ignore /smart-sizing +home-drive +clipboard"
    if [[ ! -z $use_proxychain ]] && [[ $use_proxychain == "true" ]]; then
        xfreerdp_options="$xfreerdp_options /proxy:socks5://$proxy_target:$proxy_port"
    fi
    if [[ ! -z "$use_kerberos" ]] && [[ $use_kerberos == "true" ]]; then
        echo "Using Kerberos authentication"
        xfreerdp_options="$xfreerdp_options /sec:nla /p:''"
    else
        if [[ ! -z "$ntlm_hash" ]]; then
            echo "Using NTLM authentication"
            xfreerdp_options="$xfreerdp_options /pth:$ntlm_hash"
        else
            echo "Using password authentication"
            xfreerdp_options="$xfreerdp_options /p:$password"
        fi
    fi
    echo "xfreerdp options: $xfreerdp_options"
    if $run_in_background; then
        echo "Running xfreerdp in the background"
        xfreerdp $xfreerdp_options >> $trail_log 2>&1 &
    else
        echo "Running xfreerdp in the foreground"
        xfreerdp $xfreerdp_options >> $trail_log 2>&1
    fi
}