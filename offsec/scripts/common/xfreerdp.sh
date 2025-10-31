#!/bin/bash


run_xfreerdp() {
    if [ -z  "$username" ]; then
        echo "username must be set before running xfreerdp."
        return 1
    fi
    if [[ -z "$rdp_port" ]] && [[ -z $rdp_file ]]; then
        rdp_port=3389  # Default RDP port
    fi

    if [[ -z "$rdp_ip" ]] && [[ -z $rdp_file ]]; then
        rdp_ip=$ip
    fi
    if [ -z "$trail_log" ]; then
        trail_log="trail.log"
    fi
    if [[ ! -z $run_rdp_forced ]] && [[ $run_rdp_forced == "true" ]]; then
        echo "Running xfreerdp with forced RDP connection"
    else
        if ss -tupn | grep "$rdp_ip:$rdp_port" | grep "xfreerdp"; then
            echo "RDP is already running on $rdp_ip:$rdp_port"
            return 0
        fi
    fi
    local xfreerdp_command=""
    if [[ ! -z $xfreerdp_version ]] && [[ $xfreerdp_version == "flatpak" ]]; then
        xfreerdp_command="flatpak run --command=xfreerdp com.freerdp.FreeRDP"
    elif [[ ! -z "$xfreerdp_version" ]] && [[ $xfreerdp_version == "3" ]]; then
        xfreerdp_command="xfreerdp3"
    else
        xfreerdp_version="2"
        xfreerdp_command="xfreerdp"
    fi
    local xfreerdp_options=""
    if [[ ! -z $rdp_file ]] && [[ -f $rdp_file ]]; then
        xfreerdp_options="$rdp_file"
    fi
    if [[ ! -z $rdp_ip ]]; then
        xfreerdp_options="$xfreerdp_options /v:$rdp_ip"
    fi
    if [[ ! -z $rdp_port ]]; then
        xfreerdp_options="$xfreerdp_options /port:$rdp_port"
    fi
    if [[ ! -z "$domain" ]]; then
        xfreerdp_options="$xfreerdp_options /d:$domain"
    fi
    if [[ ! -z "$username" ]]; then
        xfreerdp_options="$xfreerdp_options /u:$username"
    fi
    if [[ ! -z $use_proxychain ]] && [[ $use_proxychain == "true" ]]; then
        xfreerdp_options="$xfreerdp_options /proxy:socks5://$proxy_target:$proxy_port"
    else
        if [[ ! -z $proxy_target ]]; then
            local proxy_url=""
            if [[ ! -z $proxy_username ]]; then
                proxy_url="$proxy_username"
                if [[ ! -z $proxy_password ]]; then
                    proxy_url="$proxy_url:$proxy_password"
                fi
                proxy_url="$proxy_url@"
            fi
            proxy_url="$proxy_url$proxy_target:$proxy_port"
            xfreerdp_options="$xfreerdp_options /proxy:http://$proxy_url"
        fi
    fi
    if [[ ! -z "$use_kerberos" ]] && [[ $use_kerberos == "true" ]]; then
        echo "Using Kerberos authentication"
        xfreerdp_options="$xfreerdp_options /sec:nla /p:''"
    else
        if [[ ! -z $enable_nla ]] && [[ $enable_nla == "false" ]]; then
            if [[ $xfreerdp_version == "2" ]]; then
                    xfreerdp_options="$xfreerdp_options -sec-nla"            
            else
                xfreerdp_options="$xfreerdp_options /sec:nla:off"
            fi
        fi
        if [[ ! -z "$ntlm_hash" ]]; then
            echo "Using NTLM authentication"
            xfreerdp_options="$xfreerdp_options /pth:$ntlm_hash"
        else
            echo "Using password authentication"
            xfreerdp_options="$xfreerdp_options /p:$password"
        fi
    fi
    echo "Starting xfreerdp to connect to $rdp_ip on port $rdp_port with username $username"
    xfreerdp_options="$xfreerdp_options /cert:ignore /smart-sizing +home-drive +clipboard"
    if [[ ! -z "$xfreerdp_additional_options" ]]; then
        xfreerdp_options="$xfreerdp_options $xfreerdp_additional_options"
    fi
    echo "xfreerdp options: $xfreerdp_options"
    if $run_in_background; then
        echo "Running xfreerdp in the background"
        $xfreerdp_command $xfreerdp_options | tee >(remove_color_to_log >> $trail_log ) & #>> $trail_log 2>&1 &
    else
        echo "Running xfreerdp in the foreground"
        $xfreerdp_command $xfreerdp_options | tee >(remove_color_to_log >> $trail_log)
    fi
}