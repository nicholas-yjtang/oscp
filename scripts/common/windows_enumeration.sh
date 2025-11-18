#!/bin/bash

download_winPEAS () {
    local url="https://github.com/peass-ng/PEASS-ng/releases"
    if [[ -z $winpeas_arch ]]; then
        winpeas_arch="x64"
        echo "No winPEAS architecture specified. Defaulting to x64."
    fi
    if [ -f "winPEAS${winpeas_arch}.exe" ]; then
        echo "winPEAS${winpeas_arch}.exe already exists."
    else
        local release_tag=$(curl -s $url | grep "releases/tag" | head -n 1 | grep -oP 'tag/\K[^"]+' )
        echo "Latest release tag: $release_tag"
        local release_url="https://github.com/peass-ng/PEASS-ng/releases/expanded_assets/${release_tag}"
        echo "Release URL: $release_url"
        local winpeas_link="$(curl -s $release_url | grep winPEAS${winpeas_arch}.exe | grep -oP 'href="\K[^"]+')"
        echo "winPEAS link: $winpeas_link"
        wget "https://github.com$winpeas_link" -O winPEAS${winpeas_arch}.exe
    fi
    generate_windows_download "winPEAS${winpeas_arch}.exe"
}

download_winpeas_bat() {

    local url="https://raw.githubusercontent.com/peass-ng/PEASS-ng/refs/heads/master/winPEAS/winPEASbat/winPEAS.bat"
    if [ -f winPEAS.bat ]; then
        echo "winPEAS.bat already exists."
    else
        wget "$url" -O winPEAS.bat
    fi
    generate_windows_download "winPEAS.bat"
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

get_service_details_command() {
    if [[ -z "$1" ]]; then
        echo "Service name is required."
        return 1
    fi
    echo "Get-WmiObject win32_service -Filter \"Name='$1'\" | Select-Object *"
}

get_psconsole_history() {

    echo 'Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue -Include "ConsoleHost_history.txt" | ForEach-Object { Get-Content $_.FullName }'

}