#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source "$SCRIPTDIR/network.sh"
source "$SCRIPTDIR/add_host.sh"

setup_ad() {
    partial_ip=$(get_partial_ip)
    web04_ip=$partial_ip.72
    files04_ip=$partial_ip.73
    dc1_ip=$partial_ip.70
    client74_ip=$partial_ip.74
    client75_ip=$partial_ip.75
    client76_ip=$partial_ip.76
    add_host "web04" "$web04_ip"
    add_host "files04" "$files04_ip"
    add_host "dc1" "$dc1_ip"
    add_host "client74" "$client74_ip"
    add_host "client75" "$client75_ip"
    add_host "client76" "$client76_ip"
    add_host "corp.com" "$dc1_ip"
    add_host "web04.corp.com" "$web04_ip"
    add_host "files04.corp.com" "$files04_ip"
    add_host "dc1.corp.com" "$dc1_ip"
    add_host "client74.corp.com" "$client74_ip"
    add_host "client75.corp.com" "$client75_ip"
    add_host "client76.corp.com" "$client76_ip"
}

setup_assembling_pieces() {
    if [[ -z "$1" ]]; then
        echo "Please provide the third octet for the internal network"
        exit 1
    fi
    internal_subnet=172.16.$1
    partial_ip=$(get_partial_ip)
    winprep_ip=$partial_ip.250
    websrv1_ip=$partial_ip.244
    mailsrv1_ip=$partial_ip.242
    internal_mailsrv1_ip="$internal_subnet.254"
    internal_dcsrv1_ip="$internal_subnet.240"
    internal_internalsrv1_ip="$internal_subnet.241"
    internal_clientwk1_ip="$internal_subnet.243"
    add_host "winprep" "$winprep_ip"
    add_host "websrv1" "$websrv1_ip"
    add_host "mailsrv1" "$mailsrv1_ip"
    add_host "internalsrv1.beyond.com" "$internal_internalsrv1_ip"
    add_host "dcsrv1.beyond.com" "$internal_dcsrv1_ip"
}