#!/bin/bash

smtp_enumeration() {
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using $target_ip"        
    fi
    if [[ ! -f "log/smtp_user_enum_$target_ip.log" ]]; then
        if [[ -z $smtp_mode ]]; then
            smtp_mode="VRFY"
            echo "SMTP mode is not set, using default mode: $smtp_mode"
        fi
        if [[ -z $smtp_username_list ]]; then
            smtp_username_list="/usr/share/seclists/Usernames/Names/names.txt"
            echo "SMTP username list is not set, using default: $smtp_username_list"
        fi
        smtp-user-enum -M $smtp_mode -U $smtp_username_list -t $target_ip | tee -a "log/smtp_user_enum_$target_ip.log"
    else
        echo "SMTP user enumeration log for $target_ip already exists, skipping enumeration."
    fi
}

enumerate_smtp_auth() {
    if [[ -z $target_ip ]]; then
        echo "Target IP is not set."
        return 1
    fi
    if [[ -z $smtp_client_host ]]; then
        echo "SMTP client host is not set."
        return 1
    fi
    if [[ -z $smtp_username ]]; then
        echo "SMTP username is not set."
        return 1
    fi
    if [[ -z $smtp_password ]]; then
        echo "SMTP password is not set."
        return 1
    fi
    if [[ -z $target_users ]]; then
        target_users=users.txt
        if [[ ! -f $target_users ]]; then
            echo "Target users file $target_users does not exist."
            return 1
        fi
    fi
    # Enumerate SMTP services
    sleep_time=0.05
    echo "Enumerating SMTP services on $target_ip..."
    {
        ( 
        echo "HELO $smtp_client_host" 
        sleep $sleep_time
        echo 'AUTH LOGIN'
        sleep $sleep_time
        echo -n "$smtp_username" | base64 
        sleep $sleep_time
        echo -n "$smtp_password" | base64 
        sleep $sleep_time
        echo "MAIL FROM:$smtp_username"
        sleep $sleep_time
        while IFS= read -r target_user; do
            echo "RCPT TO:$target_user"
            sleep $sleep_time
        done < $target_users
        echo 'QUIT'
        ) | tee >(cat >&2) | telnet $target_ip 25
    } >> smtp.log 2>&1
}