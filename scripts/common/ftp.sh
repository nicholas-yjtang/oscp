#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

run_ftp() {
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP not provided, using default IP: $target_ip"
    fi
    if [[ -z $target_port ]]; then
        target_port=21
        echo "Target port not provided, using default port: $target_port"
    fi
    if [[ -z $username ]]; then
        username="anonymous"
        echo "Username not provided, using default username: $username"
    fi
    if [[ -z $password ]]; then
        password="anonymous"
        echo "Password not provided, using default password: $password"
    fi
    local target_url="ftp://$username:$password@$target_ip:$target_port"
    if [[ -z $ftp_commands ]]; then
        echo "No FTP commands provided. Going to be interactive"
        if pgrep -f "ftp ftp://$username:$password@$target_ip:$target_port" > /dev/null; then
            echo "FTP session is already active"
            return 0
        else
            ftp $target_url | tee >(remove_color_to_log >> "$log_dir/ftp_$target_ip.log")
        fi
    else
        echo "Running FTP commands on $target_ip:$target_port" 
        echo -e "$ftp_commands" > ftp_commands.txt
        ftp $target_url < ftp_commands.txt | tee >(remove_color_to_log >> "$log_dir/ftp_$target_ip.log")
    fi   

}
