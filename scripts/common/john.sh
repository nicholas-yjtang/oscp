#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

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

john_zip_password() {
    if [[ -z "$target_zip" ]]; then
        echo "Target zip file must be set before running john for zip password."
        return 1
    fi
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.$target_zip"
    else
        echo "Using provided hash file: $hash_file"
    fi
    if [[ ! -f "$hash_file" ]]; then
        echo "Running zip2john to generate hash file."
        zip2john "$target_zip" > "$hash_file"
    else
        echo "$hash_file already exists, skipping zip2john."
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

