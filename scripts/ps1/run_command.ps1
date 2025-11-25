$process_name="{process_name}";
$argument_list="{argument_list}";
$runningScripts=Get-Process -Name $process_name -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*$argument_list*" };
if ($runningScripts) {
    Write-Host "The script '$process_name' is currently running with arguments: $argument_list";
} else {
     Invoke-Command -ScriptBlock { Start-Job -ScriptBlock { {run_command} } };
}