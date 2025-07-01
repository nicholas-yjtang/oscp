#!/bin/bash
run_scp() {
    if [[ -z "$username " || -z "$password" || -z "$ip" ]]; then
        echo "username, password, or ip address is not set."
        return 
    fi
    if [[ -z "$trail_log" ]]; then
        trail_log="trail.log"
    fi
    local file="$1"
    sshpass -p $password scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "$file" $username@$ip:/home/$username/ 2>/dev/null | tee -a $trail_log
}

run_ssh() {
    if [[ -z "$username " || -z "$password" ]]; then
        echo "username, password, or ip address is not set."
        return 
    fi
    if [[ -z "$ssh_target" ]]; then
        echo "SSH target is not set, using default $ip"
        ssh_target="$ip"        
    fi
    if [[ -z "$ssh_port" ]]; then
        ssh_port=22  # Default SSH port
    fi
    if [[ -z "$trail_log" ]]; then
        trail_log="trail.log"
    fi    
    local command="$1"
    if [[ -z "$command" ]]; then
        sshpass -p $password ssh -v -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $username@$ssh_target -p $ssh_port | tee -a $trail_log
    else
        sshpass -p $password ssh -v -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $username@$ssh_target -p $ssh_port "$command" | tee -a $trail_log
    fi
}
