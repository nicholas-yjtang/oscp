#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

download_kerbrute() {
    local kerbrute_url="https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe"
    if [[ ! -f "kerbrute_windows_amd64.exe" ]]; then
        wget "$kerbrute_url" -O kerbrute_windows_amd64.exe >> $trail_log
    fi
    generate_windows_download kerbrute_windows_amd64.exe
}

create_kerbrute() {
    if [[ ! -d "kerbrute" ]]; then
        git clone https://github.com/ropnop/kerbrute.git
    fi
    if [[ -z "$go_version" ]]; then
        go_version="1.19" 
    fi 
    if [[ ! -f kerbrute/dist/kerbrute_linux_amd64 ]]; then
        echo "Building kerbrute..."
        docker run -it --rm -v $(pwd)/kerbrute:/opt/kerbrute -w /opt/kerbrute golang:$go_version /bin/bash -c "git config --global --add safe.directory /opt/kerbrute &&make linux"
    fi
    if [[ ! -f kerbrute_linux_amd64 ]]; then
        echo "Copying kerbrute binary..."
        cp kerbrute/dist/kerbrute_linux_amd64 .
    fi
}

run_kerbrute() {
    local kerbrute_command=$1
    if [[ -z $kerbrute_command ]]; then
        echo "kerbrute command is not set"
        return 1
    fi    
    if [[ -z "$domain" ]]; then
        echo "domain is not set"
        return 1
    fi
    if [[ -z $dc_ip ]]; then
        echo "dc_ip is not set"
        return 1
    fi
    if [[ ! -f "kerbrute_linux_amd64" ]]; then
        echo "kerbrute binary not found, compiling..."
        create_kerbrute
    fi
    if pgrep -f "kerbrute_linux_amd64"; then
        echo "kerbrute is already running"
        return 0
    fi
    if [[ -z $kerbrute_options ]]; then
        if [[ $kerbrute_command == "userenum" ]]; then        
            if  [[ -f usernames.txt ]]; then
                kerbrute_options="usernames.txt"
            else
                kerbrute_options="/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
            fi
        fi
    fi
    if [[ -f "$log_dir/kerbrute_$dc_ip.log" ]]; then
        echo "kerbrute log already exists for $dc_ip, skipping test."
        return 0
    fi
    local command_string="./kerbrute_linux_amd64 $kerbrute_command -d $domain --dc $dc_ip $kerbrute_options"
    echo $command_string
    eval "$command_string" |  tee >(remove_color_to_log >> "$log_dir/kerbrute_$dc_ip.log")
}

generate_names() {

    if [[ ! -f "$firstnames_file" ]]; then
        firstnames_file=firstnames.txt
        echo "Using default firstnames file: $firstnames_file"
        if [[ ! -f "$firstnames_file" ]]; then
            echo "Generating $firstnames_file from seclists"
            cp /usr/share/seclists/Usernames/Names/femalenames-usa-top1000.txt "$firstnames_file"
            cat /usr/share/seclists/Usernames/Names/malenames-usa-top1000.txt >> "$firstnames_file"
        fi
    fi
    if [[ ! -f "$lastnames_file" ]]; then           
        lastnames_file=lastnames.txt
        echo "Using default lastnames file: $lastnames_file"
        if [[ ! -f "$lastnames_file" ]]; then
            echo "Generating $lastnames_file from seclists"
            cp /usr/share/seclists/Usernames/Names/familynames-usa-top1000.txt "$lastnames_file"
        fi
    fi
    if [[ -z "$output_file" ]]; then
        output_file="usernames.txt"
        echo "Using default output file: $output_file"
    fi
    if [[ -f "$output_file" ]]; then
        echo "$output_file already exists, skipping generation"
        return 0
    fi
    for firstname in $(cat "$firstnames_file"); do
        for lastname in $(cat "$lastnames_file"); do
            echo "$firstname.$lastname" >> "$output_file"
        done
    done

}