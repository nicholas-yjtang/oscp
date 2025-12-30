$fileBytes = [System.IO.File]::ReadAllBytes("{TARGET_FILE}")
$memoryStream = New-Object IO.MemoryStream
$gzipStream = New-Object IO.Compression.GzipStream($memoryStream, [IO.Compression.CompressionMode]::Compress)
$gzipStream.Write($fileBytes, 0, $fileBytes.Length)
$gzipStream.Close()
$base64String = [Convert]::ToBase64String($memoryStream.ToArray())
[System.IO.File]::WriteAllText("{OUTPUT_FILE}", $base64String, [System.Text.Encoding]::ASCII)
$memoryStream.Close()