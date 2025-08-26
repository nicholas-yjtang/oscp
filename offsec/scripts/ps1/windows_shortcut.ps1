$wshshell = New-Object -COMObject WScript.Shell;
$shortcut_name = "{shortcut_name}";
$shortcut = $wshshell.CreateShortCut($shortcut_name);
$shortcut.TargetPath = "powershell.exe";
$shortcut.Arguments = "{cmd}";
$shortcut.Save();