#!/bin/bash

download_winPEAS () {
    if [ -f winPEASx64.exe ]; then
        echo "winPEASx64.exe already exists."
    else
        wget https://github.com/peass-ng/PEASS-ng/releases/download/20250701-bdcab634/winPEASx64.exe -O winPEASx64.exe
    fi
    generate_windows_download "winPEASx64.exe"
}

download_winpeas () {
    download_winPEAS
}

get_powershell_search_commands() {
    echo 'Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Include "*.txt","*.log","*.xml","*.ini" | Where-Object { $_.FullName -notmatch "microsoft|windows" } | ForEach-Object { "$($_.Directory.FullName)\$($_.Name)"}'
    echo 'Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue -Include "*.txt","*.log","*.xml","*.ini" | ForEach-Object { "$($_.Directory.FullName)\$($_.Name)"}'
    echo 'Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Directory.FullName)\$($_.Name)"}'
    echo 'Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Include "*.kdbx" | Where-Object { $_.FullName -notmatch "microsoft|windows" } | ForEach-Object { "$($_.Directory.FullName)\$($_.Name)"}'
    echo 'Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Include "*.txt","*.log","*.xml","*.ini" | Where-Object { $_.FullName -notmatch "microsoft|windows" } | Select-String -Pattern "password"'
    echo 'Find possibly sam/system dumps'
    echo 'Get-ChildItem -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "^reg"'    
    get_powershell_services_command
    get_powershell_scheduled_tasks_command
    get_psconsole_history

}

get_powershell_services_command(){
    echo 'Get-Service'
    echo 'Get-WmiObject win32_service | Select-Object Name, PathName'
    echo 'Get-WmiObject Win32_Service | Select-Object Name, DisplayName, StartName, State | Format-Table -AutoSize'
}

get_command_search_commands() {
    echo 'cd c:\;'
    echo 'dir /s /b | findstr "txt$ log$ ini$ conf$ properties$ xml$" | findstr /v "windows microsoft"'
}

get_powershell_scheduled_tasks_command() {

    echo 'Get-ScheduledTask | ForEach-Object {'
    echo '    $taskName = $_.TaskName'
    echo '    $taskPath = $_.TaskPath'
    echo '    $taskActions = $_.Actions'
    echo '    Write-Host "Task Name: $taskName"'
    echo '    Write-Host "Task Path: $taskPath"'
    echo '    if ($taskActions) {'
    echo '        foreach ($action in $taskActions) {'
    echo '            Write-Host "  Action Type: $($action.ActionType)"'
    echo '            Write-Host "  Executable: $($action.Execute)"'
    echo '            Write-Host "  Arguments: $($action.Arguments)"'
    echo '            Write-Host "  Working Directory: $($action.WorkingDirectory)"'
    echo '        }'
    echo '    } else {'
    echo '        Write-Host "  No actions defined for this task."'
    echo '    }'
    echo '    Write-Host "" # Add a blank line for readability'
    echo '}'
}

test_anonymous_smb() {
    if [[ -z $target_ip ]]; then
        echo "Target IP is not set. Please set the target_ip variable."
        return 1
    fi
    echo 'Testing anonymous SMB access...'
    local guest=$(netexec smb "$target_ip" -u test -p test| grep Guest)
    if [[ ! -z "$guest" ]]; then
        echo "Anonymous SMB access is allowed on $target_ip"
        netexec smb "$target_ip" -u test -p test --shares
    else
        echo "Anonymous SMB access is NOT allowed on $target_ip"
    fi
}

get_psconsole_history() {

    echo 'Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue -Include "ConsoleHost_history.txt" | ForEach-Object { Get-Content $_.FullName }'

}