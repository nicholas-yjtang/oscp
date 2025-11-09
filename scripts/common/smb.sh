#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

smb_enumerate() {
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using $target_ip"        
    fi
    if [[ ! -f "log/enum4linux_$target_ip.log" ]]; then
        enum4linux $target_ip | tee -a "log/enum4linux_$target_ip.log"
        nmap -p 139,445 --script=smb-enum*,smb-os*,smb-vuln* $target_ip -oN "log/nmap_smb_enum_$target_ip.log"
    fi
}

run_smbclient() {

    local command=$1    
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using $target_ip"
    fi
    if [[ -z $smb_share ]]; then
        smb_share="IPC$"
        echo "SMB share is not set, using default share: $smb_share"
    fi
    local smb_authentication=""
    if [[ ! -z $username ]] && [[ ! -z $password ]]; then
        smb_authentication="-U $username%$password"
    elif [[ ! -z $username ]] && [[ -z $password ]]; then
        smb_authentication="-U $username --no-pass"
    else
        smb_authentication="-N"
    fi
    if pgrep -f "smbclient //$target_ip/$smb_share"; then
        echo "smbclient session to //$target_ip/$smb_share already running"
        return 0
    fi    
    if [[ ! -z $command ]]; then
        command="-c \"$command\""
    fi
    local command_string="smbclient //$target_ip/$smb_share $smb_authentication $command"
    echo $command_string
    eval $command_string | tee -a "log/smbclient_$target_ip.log"
}