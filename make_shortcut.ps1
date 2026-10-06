$desktop = [Environment]::GetFolderPath('Desktop')
$assetsDir = "$desktop\Launcher Assets\peek-a-boo\"
if (-not (Test-Path $assetsDir)) { New-Item -ItemType Directory -Path $assetsDir -Force | Out-Null }

$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("$desktop\peek-a-boo.lnk")
$shortcut.TargetPath = "C:\Users\HarpStar\peek-a-boo\launch.bat"
$shortcut.WorkingDirectory = "C:\Users\HarpStar\peek-a-boo"
$shortcut.Description = "Peek-a-Boo OSINT Dashboard"
$shortcut.IconLocation = "C:\Users\HarpStar\AppData\Local\hermes\hermes-agent\venv\Scripts\pythonw.exe,0"
$shortcut.Save()

Write-Output "Shortcut created: $desktop\peek-a-boo.lnk"

if (Test-Path "$desktop\peek-a-boo.lnk") {
    Write-Output 'VERIFIED: shortcut exists'
} else {
    Write-Output 'FAILED: shortcut not found'
}

Write-Output "Assets dir: $assetsDir"