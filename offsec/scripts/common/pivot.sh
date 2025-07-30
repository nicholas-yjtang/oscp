#!/bin/bash

get_chisel() {
    local chisel_file=$1
    if [[ -z "$chisel_file" ]]; then
        chisel_file="windows_amd64"        
    fi
    local chisel_url="https://github.com/jpillora/chisel/releases/expanded_assets/v1.10.1"
    local chisel_assets=$(curl -s $chisel_url | grep -oP 'href="\K[^"]+')    
    while read -r line ; do
        if [[ $line == *$chisel_file* && $line == *gz* ]] ; then            
            wget -q https://github.com$line -O "chisel_$chisel_file"'.gz'
            gunzip "chisel_$chisel_file"'.gz'
            if [[ $chisel_file == "windows"* ]] ; then
                mv "chisel_$chisel_file" chisel.exe
            else
                mv "chisel_$chisel_file" chisel
                chmod +x chisel
            fi
        fi
    done <<< "$chisel_assets"
}

compile_chisel() {
    local go_version=$1
    if [[ -z "$go_version" ]]; then
        go_version="1.19"
    fi
    local chisel_version=$2
    if [[ -z "$chisel_version" ]]; then
        chisel_version="1.10.1"
    fi
    if [[ -f "chisel" ]]; then
        echo "Chisel binary already exists, skipping compilation."
        return 1
    fi
    local chisel_src="https://github.com/jpillora/chisel/archive/refs/tags/v$chisel_version.tar.gz"
    if [[ ! -f "chisel.tar.gz" ]]; then
        wget -q $chisel_src -O chisel.tar.gz
        tar xvf chisel.tar.gz
    fi    
    sed -i 's/0\.0\.0-src/'$chisel_version'/g' chisel-$chisel_version/share/version.go
    docker run -it --rm -v $(pwd)/chisel-$chisel_version:/opt/chisel -w /opt/chisel golang:$go_version go build main.go
    cp chisel-$chisel_version/main chisel
}

start_chisel_server() {
    if [ ! -f "chisel" ]; then
        echo "Chisel binary not found. Please compile or download it first."
        return 1
    fi
    chisel_server_port=$1
    if [ -z "$chisel_server_port" ]; then
        chisel_server_port=8080
    fi
    if [ -z "$chisel_server_ip" ]; then
        chisel_server_ip=$(get_host_ip)
    fi
    if [ -z "$chisel_server_options" ]; then
        chisel_server_options="--reverse"
    fi
    if pgrep -f "chisel server"; then
        echo "Chisel server is already running."
        return 0
    fi
    echo "Starting Chisel server on port $chisel_server_port... with $chisel_server_options"
    ./chisel server --port $chisel_server_port $chisel_server_options 2>&1 | tee -a $log_dir/chisel.log &
}


stop_chisel_server() {
    if pgrep -f "chisel server"; then
        echo "Stopping Chisel server..."
        pkill -f "chisel server"
    else
        echo "No Chisel server is running."
    fi
}

get_chisel_client_commands() {

    chisel_client_options=$1
    if [ ! -z "$chisel_client_options" ]; then
        chisel_client_options+=" "
    fi
    if [[ $(ps -ef | grep -v grep | grep "chisel server") == *reverse* ]]; then
        chisel_client_options+="R:"
    else
        chisel_client_options+=""
    fi
    if [ -z "$chisel_local_interface" ]; then
        chisel_local_interface=127.0.0.1
    fi
    chisel_client_options+="$chisel_local_interface"':'
    if [ -z "$chisel_local_port" ]; then
        chisel_local_port=1080        
    fi
    chisel_client_options+="$chisel_local_port:"
    if [ ! -z "$chisel_remote_host" ]; then
        chisel_client_options+="$chisel_remote_host:"
    fi
    if [ ! -z "$chisel_remote_port" ]; then
        chisel_client_options+="$chisel_remote_port"
    fi
    if [ -z "$chisel_remote_host" ]; then
        chisel_client_options+="socks"
    fi
    if [ -z "$chisel_client_protocol" ]; then
        chisel_client_protocol="tcp"
    fi
    chisel_client_options+="/$chisel_client_protocol"
    echo "chisel client $chisel_server_ip:$chisel_server_port $chisel_client_options"
}

wait_for_chisel_client_connect() {
    if [ -z "$chisel_local_port" ]; then
        chisel_local_port=1080
    fi
    local timeout=$1
    if [ -z "$timeout" ]; then
        timeout=30
    fi
    echo "Waiting for Chisel client to connect..."
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        if ss -ntplu | grep -q ":$chisel_local_port"; then
            ss -ntplu | grep ":$chisel_local_port"
            return 0
        fi
        sleep 1
    done
    echo "Chisel client did not connect within $timeout seconds."
    return 1
}

is_chisel_client_connected() {
    if [ -z "$chisel_local_port" ]; then
        chisel_local_port=1080
    fi
    if ss -ntplu | grep -q ":$chisel_local_port"; then
        echo "Chisel client is connected on port $chisel_local_port."
        return 0
    else
        echo "Chisel client is not connected on port $chisel_local_port."
        return 1
    fi
}  