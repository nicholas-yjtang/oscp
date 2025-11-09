#!/bin/bash

convert_zip_to_hashcat() {
    if [[ -z $target_zip ]]; then
        echo "Please set a target_zip file"
        return 1
    fi
    if [[ -z "$hash_file" ]]; then
        echo "Please set a hash_file"
        return 1
    fi

    local url="https://github.com/hashstation/zip2hashcat/archive/refs/heads/main.zip"    
    if [[ ! -d zip2hashcat-main ]]; then
        echo "Directory zip2hashcat-main does not exist."
        wget "$url" -O zip2hashcat.zip
        unzip zip2hashcat.zip
    fi
    if [[ ! -f zip2hashcat ]]; then
        pushd zip2hashcat-main || return 1 
        make
        cp zip2hashcat ../
        popd || exit 1
    fi
    ./zip2hashcat $target_zip > $hash_file
}

hashcat_generic_kdf() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.kdf"
    else
        echo "Using provided hash file: $hash_file"
    fi
    hash_mode=10900  # PBKDF2-HMAC-SHA256 hash mode
    hashcat_generic
}

hashcat_zip() {

    if [[ -z "$hash_file" ]]; then
        hash_file=hashes.zip
        echo "Setting default hash_file to $hash_file"
    else
        echo "Using provided hash file: $hash_file"
    fi
    hash_mode=13600
    hashcat_generic

}

# linux shadow file contents
hashcat_sha512() {

    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.sha512"
    else
        echo "Using provided hash file: $hash_file"
    fi
    hash_mode=1800  # SHA-512 hash mode
    hashcat_generic
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

hashcat_sha1() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.sha1"
    else
        echo "Using provided hash file: $hash_file"
    fi
    hash_mode=100  # SHA-1 hash mode
    hashcat_generic
}

hashcat_sha256crypt() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.sha256crypt"
    else
        echo "Using provided hash file: $hash_file"
    fi
    hash_mode=7400  # SHA-256 crypt unix
    hashcat_generic
}

hashcat_sha512crypt() {
    if [[ -z $hash_file ]]; then
        hash_file="hashes.sha512crypt"
    else
        echo "Using provided hash file: $hash_file"
    fi
    hash_mode=1800  # SHA-512 crypt unix
    hashcat_generic
}

hashcat_md5crypt() {
    if [[ -z $hash_file ]]; then
        hash_file="hashes.md5crypt"
    else
        echo "Using provided hash file: $hash_file"
    fi
    hash_mode=500  # MD5 crypt unix
    hashcat_generic
}

hashcat_asrep_kerberoast() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.asreproast"
    else
        echo "Using provided hash file: $hash_file"
    fi
    hash_mode=18200  # AS-REP Kerberos hash mode
    hashcat_generic
}

hashcat_show() {    
    if [[ -z "$hash_file" ]]; then
    #|| [[ -z "$hash_mode" ]]; then
        echo "Hash file must be set before running hashcat --show."
        return 1
    fi
    local hash_mode_option=""
    if [[ ! -z "$hash_mode" ]]; then
        hash_mode_option="-m $hash_mode"
    fi
    local cmd="hashcat --show $hash_mode_option $hash_file"
    if use_host_for_cracking; then
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

hashcat_md5() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.md5"
    else
        echo "Using provided hash file: $hash_file"
    fi
    hash_mode=0  # MD5 hash mode
    hashcat_generic

}
hashcat_lm() {

    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.lm"
    else
        echo "Using provided hash file: $hash_file"
    fi
    hash_mode=3000  # LM hash mode
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

hashcat_php_bcrypt() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.phpbcrypt"
    else
        echo "Using provided hash file: $hash_file"
    fi    
    hash_mode=3200  # bcrypt hash mode
    hashcat_generic
}

hashcat_ssh_password() {
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
        ssh2john "$identity" > "$hash_file"
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
    if [[ ! -z $enable_hashcat_rules ]] && [[ $enable_hashcat_rules == "false" ]]; then
        hashcat_rule=""
    fi
    local hashcat_rule_option=""
    if [[ ! -z "$hashcat_rule" ]]; then
        hashcat_rule_option="-r $hashcat_rule"
    fi
    echo "$hash_file found, running hashcat for hash mode $hash_mode"
    sudo dos2unix "$hash_file"
    local cmd="hashcat -m $hash_mode $hash_file $hashcat_wordlist $hashcat_rule_option --force"
    if use_host_for_cracking; then
        scp "$hash_file" "$host_username@$host_computername:~/$hash_file"
        ssh "$host_username@$host_computername" "$cmd"
    else
        eval "$cmd"
    fi

}