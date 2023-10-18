Write-Output "Installing Ghidra Deep Links"
Write-Output "This will install a handler for the disas:// uri scheme for the current user."
$confirm = Read-Host "Are you sure you wish to continue? [y/N]"
if (-not ($confirm -eq 'y')) {
    Return "Exiting..."
}

Copy-Item -Path ".\os\win\push_to_socket.ps1" -Destination "~\.ghidra\push_to_socket.ps1"

Write-Output "Installing scheme handler..."

Push-Location
Set-Location -Path Registry::HKEY_CURRENT_USER\Software\Classes\
New-Item -Force -Path disas
Set-ItemProperty -Path disas -Name "(default)" -Value "URL:Ghidra Protocol"
New-ItemProperty -Force -Path disas -Name "URL Protocol" -PropertyType String
New-Item -Force -Path disas\DefaultIcon
New-Item -Force -Path disas\shell
New-Item -Force -Path disas\shell\open
New-Item -Force -Path disas\shell\open\command
Set-ItemProperty -Path disas\shell\open\command -Name "(default)" -Value "powershell.exe -NoProfile -WindowStyle Minimized -ExecutionPolicy Bypass -File $HOME\.ghidra\push_to_socket.ps1 %1"
Pop-Location

Return "Done."
