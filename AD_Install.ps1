<#AD_Install.ps1

Author: Franck FERMAN - fferman@protonmail.ch
Version: 1.0

Description:
Useful scripts for automating the process of installation and configuration of an active directory under Windows Server.
#>

function Check_AdminRights
{
$is_Admin=(New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

switch($is_Admin)
{
    True{main}
    False{Write-Host "Error, please run Powershell in administrator mode." -ForegroundColor red}
    default{Write-Host "Error 520: Unknown Error." -ForegroundColor red}
}
}

function main 
{
$script:Get_WindowTitle=$host.ui.RawUI.WindowTitle
$host.ui.RawUI.WindowTitle="AD_Install_Automatization - Franck FERMAN"

Clear-Host
Write-Host ""
Write-Host "                            _ood>HHHHZ?#M#b-\.                  " -ForegroundColor green
Write-Host "                        .\HMMMMMR?M\M6b.... ....v.              " -ForegroundColor green
Write-Host "                     .. .MMMMMMMMMMHMMM#$.      ..~o.           " -ForegroundColor green
Write-Host "                   .   .HMMMMMMMMMM.. .           ?MP?.         " -ForegroundColor green
Write-Host "                  . |MMMMMMMMMMM.                 ..Hb$\        " -ForegroundColor green
Write-Host "                 -  |MMMMHH##M.                     HMMH?       " -ForegroundColor green
Write-Host "                -   TTM|     >..                   \HMMMMH      " -ForegroundColor green
Write-Host "               :     |MM\.#-..$~b\.                .MMMMMM+     " -ForegroundColor green
Write-Host "              .       ...H$#        -               HMMMMMM|    " -ForegroundColor green
Write-Host "              :            *\v,#MHddc.              .9MMMMMb    " -ForegroundColor green
Write-Host "              .               MMMMMMMM##\             .MM:HM    " -ForegroundColor green
Write-Host "              -          .  .HMMMMMMMMMMRo_.              |M    " -ForegroundColor green
Write-Host "              :             |MMMMMMMMMMMMMMMM#\           :M    " -ForegroundColor green
Write-Host "              -              .HMMMMMMMMMMMMMM.            |T    " -ForegroundColor green
Write-Host "              :               .*HMMMMMMMMMMM.             H.    " -ForegroundColor green
Write-Host "               :                MMMMMMMMMMM|             |T     " -ForegroundColor green
Write-Host "                ;               MMMMMMMM?.              ./      " -ForegroundColor green
Write-Host "                 `              MMMMMMH.               ./'      " -ForegroundColor green
Write-Host "                  -            |MMMH#.                 .        " -ForegroundColor green
Write-Host "                   `           .MM*                . .          " -ForegroundColor green
Write-Host "                     _          #M: .    .       .-'            " -ForegroundColor green
Write-Host "                        .          ..         .-'               " -ForegroundColor green
Write-Host "                           '-.-~ooHH__,,v~----                  " -ForegroundColor green
Write-Host ""
Write-Host "          _____    _____           _        _ _                          " -ForegroundColor green
Write-Host "    /\   |  __ \  |_   _|         | |      | | |                         " -ForegroundColor green
Write-Host "   /  \  | |  | |   | |  _ __  ___| |_ __ _| | |                         " -ForegroundColor green
Write-Host "  / /\ \ | |  | |   | | | '_ \/ __| __/ _` | | |                         " -ForegroundColor green
Write-Host " / ____ \| |__| |  _| |_| | | \__ \ || (_| | | |                         " -ForegroundColor green
Write-Host "/_/    \_\_____/  |_____|_| |_|___/\__\__,_|_|_|       _   _             " -ForegroundColor green
Write-Host "    /\        | |                      | | (_)        | | (_)            " -ForegroundColor green
Write-Host "   /  \  _   _| |_ ___  _ __ ___   __ _| |_ _ ______ _| |_ _  ___  _ __  " -ForegroundColor green
Write-Host "  / /\ \| | | | __/ _ \| '_ ` _ \ / _` | __| |_  / _` | __| |/ _ \| '_ \ " -ForegroundColor green
Write-Host " / ____ \ |_| | || (_) | | | | | | (_| | |_| |/ / (_| | |_| | (_) | | | |" -ForegroundColor green
Write-Host "/_/    \_\__,_|\__\___/|_| |_| |_|\__,_|\__|_/___\__,_|\__|_|\___/|_| |_|" -ForegroundColor green
Write-Host "                                                                         " -ForegroundColor green
Write-Host ""
Write-Host ""
Write-Host "Hello dear " -NoNewline
Write-Host "$env:UserName " -NoNewLine -ForegroundColor green
Write-Host "and welcome to " -NoNewLine
Write-Host "AD Install Automatization" -NonewLine -ForegroundColor green
Write-Host "."
Write-Host ""
Write-Host "1 - Change IP Addressing."
Write-Host "2 - Miscellaneous functions."
Write-Host "3 - Renaming the computer."
Write-Host "4 - Installation of the roles."
Write-Host "5 - Create forest and domain."
Write-Host ""
Write-Host "9 - Quit the program." -ForegroundColor red
Write-Host ""

$userChoice = Read-Host "Your choice"
switch($userChoice)
{
    1{ChangeIPAddr}
    2{Miscellaneous}
    3{Rename_Computer}
    4{Roles_Install}
    5{Create_Forest}
    9{Write-Host "";pause;$host.ui.RawUI.WindowTitle="$Get_WindowTitle";exit}
    default{Write-Host "`nInfo : " -NoNewLine;Write-Host "Error 400: The query syntax is incorrect." -ForegroundColor red;Write-Host "";pause;Clear-Host;main}
}
}

function ChangeIPAddr
{
Clear-Host
$IPAddr=Read-Host "What IP address do you want to assign to your machine (example: 192.168.0.1)"
$CIDR=Read-Host "Which CIDR would you like to assign to your machine (example: 24)"
$DNSAddr=Read-Host "What DNS address do you want to assign to your machine (example: 127.0.0.1, 1.1.1.1)"
$EtherName=Read-Host "What name do you want to assign to the network card on your machine (example: LAN)"

New-NetIPAddress -IPAddress "192.168.0.1" -PrefixLength "$CIDR" -InterfaceIndex (Get-NetAdapter).ifIndex -DefaultGateway "192.168.0.254"
Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter).ifIndex -ServerAddresses ($DNSAddr)
Rename-NetAdapter -Name (Get-NetAdapter).Name -NewName $EtherName
pause
main
}

function Miscellaneous 
{
Clear-Host
Write-Host "`nOngoing action : " -NoNewLine
Write-Host "Changing power settings." -ForegroundColor green
powercfg /S 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

Write-Host "`nOngoing action : " -NoNewLine
Write-Host "Disabling fast startup." -ForegroundColor green
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d "0" /f

Write-Host "`nOngoing action : " -NoNewLine
Write-Host "Changing the default state of the Num Lock key." -ForegroundColor green
Set-ItemProperty -Path 'Registry::HKU\.DEFAULT\Control Panel\Keyboard' -Name "InitialKeyboardIndicators" -Value "2"

Write-Host "`nOngoing action : " -NoNewLine
Write-Host "Performance optimization." -ForegroundColor green
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name "VisualFXSetting" -Type DWORD -Value "2"

Write-Host "`nOngoing action : " -NoNewLine
Write-Host "NTP synchronization." -ForegroundColor green
Write-Host ""
w32tm /resync /force

Write-Host "`nOngoing action : " -NoNewLine
Write-Host "Service Activation: Remote Registry." -ForegroundColor green
Set-Service -Name "RemoteRegistry" -Status running -StartupType automatic

Write-Host "`nOngoing action : " -NoNewLine
Write-Host "Added a registry key for creating a shortcut." -ForegroundColor green
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 1 /f

Write-Host "`nOngoing action : " -NoNewLine
Write-Host "Added a registry key for creating a shortcut." -ForegroundColor green
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 1 /f

Write-Host ""
pause
Clear-Host
main
}

function Rename_Computer
{
Clear-Host
$Computer_Number=Read-Host "Computer number (example: win-srv-01)"
Write-Host ""
Rename-Computer -NewName "$Computer_Number" -Force -Restart

Write-Host ""
pause
main
}

function Roles_Install
{
Clear-Host
$Features=@("RSAT-AD-Tools","AD-Domain-Services","DNS","DHCP")

    Foreach($Feature in $Features){
        Write-Host "Feature $Feature will be installed now.";Add-WindowsFeature -Name $Feature -IncludeAllSubFeature -IncludeManagementTools
    }

Restart-Computer
}

function Create_Forest 
{
$DomainNameDNS="tesla.local"
$DomainNameNetbios="TESLA"

$ForestConfiguration=@{
'-DatabasePath'='C:\Windows\NTDS';
'-DomainMode'='Default';
'-DomainName'=$DomainNameDNS;
'-DomainNetbiosName'=$DomainNameNetbios;
'-ForestMode'='Default';
'-InstallDns'=$true;
'-LogPath'='C:\Windows\NTDS';
'-NoRebootOnCompletion'=$false;
'-SysvolPath'='C:\Windows\SYSVOL';
'-Force'=$true;
'-CreateDnsDelegation'=$false }

Import-Module ADDSDeployment
Install-ADDSForest @ForestConfiguration

pause
Clear-Host
main
}

Check_AdminRights
