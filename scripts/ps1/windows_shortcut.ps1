$wshshell = New-Object -COMObject WScript.Shell;
$shortcut_name = "{shortcut_name}";
$shortcut = $wshshell.CreateShortCut($shortcut_name);
$shortcut.TargetPath = "{target_path}";
$shortcut.IconLocation = "{icon_location}";
$shortcut.Arguments = "{arguments}";
$shortcut.Save();