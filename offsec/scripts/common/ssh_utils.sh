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
    sshpass -p $password scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "$file" $username@$ip:/home/$username/ 2>/dev/null | tee >(remove_color_to_log >> $trail_log)
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
    if [[ -z "$ssh_options" ]]; then
        echo "No additional ssh options set"
    fi
    local command="$1"
    if [[ -z "$command" ]]; then
        echo "Running SSH command on $ssh_target as $username with port $ssh_port" 
        sshpass -p $password ssh -v  $ssh_options -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $username@$ssh_target -p $ssh_port | tee >(remove_color_to_log >> $trail_log)
    else
        sshpass -p $password ssh -v $ssh_options -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $username@$ssh_target -p $ssh_port "$command" | tee >(remove_color_to_log >> $trail_log)
    fi
}

run_ssh_identity() {
    
    if [[ -z "$username " || -z "$identity" ]]; then
        echo "username,or identity is not set."
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
        ssh -i $identity  -v -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $username@$ssh_target -p $ssh_port | tee >(remove_color_to_log >> $trail_log)
    else
        ssh -i $identity  -v -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $username@$ssh_target -p $ssh_port "$command" | tee >(remove_color_to_log >> $trail_log)
    fi

}

get_ssh_command() {
    local ssh_target="$1"
    local ssh_username="$2"
    local ssh_port="$3"
    if [[ ! -z "$ssh_port" ]]; then
        ssh_port="-p $ssh_port"
    else
        ssh_port=""
    fi
    echo "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $ssh_username@$ssh_target $ssh_port"
}

get_ssh_local_port_forwarding() {
    if [[ -z "$ssh_target" ]]; then
        echo "ssh_target is not set."
        return
    fi
    if [[ -z "$ssh_username" ]]; then
        echo "ssh_username is not set."
        return
    fi
    if [[ -z "$remote_ip" || -z "$remote_port" ]]; then
        echo "Remote IP, or Remote Port is not set."
        return
    fi
    if [[ -z "$ssh_port" ]]; then
        ssh_port=22  # Default SSH port
    fi
    if [[ -z "$local_ip" ]]; then
        local_ip=0.0.0.0
    fi    
    if [[ -z "$local_port" ]]; then
        local_port=4443
    fi    
    if [[ ! -z "$ssh_password" ]]; then
        echo "sshpass -p $ssh_password ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -N -L $local_ip:$local_port:$remote_ip:$remote_port $ssh_username@$ssh_target -p $ssh_port &"
    else
        echo "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -N -L $local_ip:$local_port:$remote_ip:$remote_port $ssh_username@$ssh_target -p $ssh_port"
    fi     
}

get_ssh_local_port_dynamic() {
    if [[ -z "$ssh_target" ]]; then
        echo "ssh_target is not set."
        return
    fi
    if [[ -z "$ssh_username" ]]; then
        echo "ssh_username is not set."
        return
    fi
    if [[ -z "$ssh_port" ]]; then
        ssh_port=22  # Default SSH port
    fi
    if [[ -z "$local_ip" ]]; then
        local_ip=0.0.0.0
    fi    
    if [[ -z "$local_port" ]]; then
        local_port=4443
    fi  
    if [[ ! -z "$ssh_password" ]]; then
        echo "sshpass -p $ssh_password ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -N -D $local_ip:$local_port $ssh_username@$ssh_target -p $ssh_port &"
    else
        echo "ssh -v -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -N -D $local_ip:$local_port $ssh_username@$ssh_target -p $ssh_port"
    fi         

}

get_ssh_remote_port_forwarding() {
    if [[ -z "$ssh_target" ]]; then
        ssh_target=$(get_host_ip)        
    fi
    if [[ -z "$ssh_username" ]]; then
        ssh_username=offsec        
    fi
    if [[ -z "$ssh_port" ]]; then
        ssh_port=22  # Default SSH port
    fi
    if [[ -z "$local_ip" ]]; then
        local_ip=127.0.0.1
    fi
    if [[ -z "$local_port" ]]; then
        local_port=4443
    fi
    if [[ -z "$remote_ip" || -z "$remote_port" ]]; then
        echo "Remote IP, or Remote Port is not set."
        return
    fi
    echo "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -N -R $local_ip:$local_port:$remote_ip:$remote_port  $ssh_username@$ssh_target -p $ssh_port"
}

get_ssh_remote_port_dynamic() {
    if [[ -z "$ssh_target" ]]; then
        ssh_target=$(get_host_ip)        
    fi
    if [[ -z "$ssh_username" ]]; then
        ssh_username=offsec        
    fi
    if [[ -z "$ssh_port" ]]; then
        ssh_port=22  # Default SSH port
    fi
    if [[ -z "$local_ip" ]]; then
        local_ip=127.0.0.1
    fi
    if [[ -z "$local_port" ]]; then
        local_port=4443
    fi
    echo "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -N -R $local_ip:$local_port  $ssh_username@$ssh_target -p $ssh_port"
}

get_ssh_remote_port_forwarding_plink() {
   if [[ -z "$ssh_target" ]]; then
        ssh_target=$(get_host_ip)        
    fi
    if [[ -z "$ssh_username" ]]; then
        ssh_username=offsec        
    fi
    if [[ -z "$ssh_password" ]]; then
        ssh_password="offsec"        
    fi
    if [[ -z "$ssh_port" ]]; then
        ssh_port=22  # Default SSH port
    fi
    if [[ -z "$local_ip" ]]; then
        local_ip=127.0.0.1
    fi
    if [[ -z "$local_port" ]]; then
        local_port=4443
    fi
    if [[ -z "$remote_ip" || -z "$remote_port" ]]; then
        echo "Remote IP, or Remote Port is not set."
        return
    fi
    echo "cmd /c echo y | .\plink.exe -ssh -l $ssh_username -pw $ssh_password -R $local_ip:$local_port:$remote_ip:$remote_port $ssh_target"

}

get_netsh_command() {
    if [[ -z "$remote_ip" || -z "$remote_port" ]]; then
        echo "Remote IP, or Remote Port is not set."
        return
    fi
    if [[ -z "$local_port" ]]; then
        local_port=4443
    fi
    if [[ -z "$local_ip" ]]; then
        local_ip=127.0.0.1
    fi
    echo "netsh interface portproxy set v4tov4 listenport=$local_port listenaddress=$local_ip connectport=$remote_port connectaddress=$remote_ip"
    echo "netsh advfirewall firewall add rule name=\"port_forward_ssh_$local_port\" dir=in action=allow protocol=TCP localip=$local_ip localport=$local_port"
    echo "netsh advfirewall firewall delete rule name=\"port_forward_ssh_$local_port\""
    echo "netsh interface portproxy delete v4tov4 listenport=$local_port listenaddress=$local_ip"

}