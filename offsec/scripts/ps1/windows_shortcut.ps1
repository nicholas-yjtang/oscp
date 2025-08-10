$wshshell = New-Object -COMObject WScript.Shell;
$shortcut_name = "{shortcut_name}";
$shortcut = $wshshell.CreateShortCut($shortcut_name);
$shortcut.TargetPath = "cmd.exe";
$shortcut.Arguments = "/Q /C {cmd}";
$shortcut.Save();


