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