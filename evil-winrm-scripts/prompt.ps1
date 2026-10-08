# Override evil-winrm prompt to include target hostname for log attribution.
# Loaded automatically via: evil-winrm -s ~/.local/share/evil-winrm-scripts/
# $env:COMPUTERNAME is evaluated on the REMOTE machine.
function prompt {
    "*Evil-WinRM* PS [$env:COMPUTERNAME] $PWD> "
}
