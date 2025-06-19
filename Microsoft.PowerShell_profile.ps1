### PowerShell Profile Refactor
### Version 1.03 - Refactored

# Initial GitHub.com connectivity check with 1 second timeout
$canConnectToGitHub = Test-Connection github.com -Count 1 -Quiet

# Import Modules and External Profiles
# Ensure Terminal-Icons module is installed before importing
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module -Name Terminal-Icons
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

# Check for Profile Updates
function Update-Profile {
    if (-not $global:canConnectToGitHub) {
        Write-Host "Skipping profile update check due to GitHub.com not responding within 1 second." -ForegroundColor Yellow
        return
    }

    try {
        $url = "https://raw.githubusercontent.com/rookie-eyes/powershell-profile/main/Microsoft.PowerShell_profile.ps1"
        $oldhash = Get-FileHash $PROFILE
        Invoke-RestMethod $url -OutFile "$env:temp/Microsoft.PowerShell_profile.ps1"
        $newhash = Get-FileHash "$env:temp/Microsoft.PowerShell_profile.ps1"
        if ($newhash.Hash -ne $oldhash.Hash) {
            Copy-Item -Path "$env:temp/Microsoft.PowerShell_profile.ps1" -Destination $PROFILE -Force
            Write-Host "Profile has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        }
    } catch {
        Write-Error "Unable to check for `$profile updates"
    } finally {
        Remove-Item "$env:temp/Microsoft.PowerShell_profile.ps1" -ErrorAction SilentlyContinue
    }
}
Update-Profile
function Update-PowerShell {
    if (-not $global:canConnectToGitHub) {
        Write-Host "Skipping PowerShell update check due to GitHub.com not responding within 1 second." -ForegroundColor Yellow
        return
    }

    try {
        Write-Host "Checking for PowerShell updates..." -ForegroundColor Cyan
        $updateNeeded = $false
        $currentVersion = $PSVersionTable.PSVersion.ToString()
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl
        $latestVersion = $latestReleaseInfo.tag_name.Trim('v')
        if ($currentVersion -lt $latestVersion) {
            $updateNeeded = $true
        }

        if ($updateNeeded) {
            Write-Host "Updating PowerShell..." -ForegroundColor Yellow
            winget upgrade "Microsoft.PowerShell" --accept-source-agreements --accept-package-agreements
            Write-Host "PowerShell has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        } else {
            Write-Host "Your PowerShell is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to update PowerShell. Error: $_"
    }
}
Update-PowerShell

# Simple function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin {

    [CmdletBinding(DefaultParameterSetName='NoCommand')]
    param (
        [Parameter(Position=0, ValueFromRemainingArguments=$true, ParameterSetName='Command')]
        [string[]]$Command
    )

    $powerShellExecutable = $null

    if ($PSVersionTable.PSEdition -eq 'Core') {
        $powerShellExecutable = Join-Path $PSHOME "pwsh.exe"
        if (-not (Test-Path $powerShellExecutable)) {
            $powerShellExecutable = "$($env:ProgramFiles)\PowerShell\7\pwsh.exe"
            if (-not (Test-Path $powerShellExecutable)) {
                Write-Error "Could not locate 'pwsh.exe' for PowerShell 7. Please ensure PowerShell 7 is installed correctly."
                return
            }
        }
    } else {
        $powerShellExecutable = Join-Path $PSHOME "powershell.exe"
    }
    if (-not (Test-Path $powerShellExecutable)) {
        Write-Error "Could not locate the PowerShell executable at '$powerShellExecutable'. Please ensure PowerShell is installed correctly."
        return
    }
    if (-not $powerShellExecutable) {
        Write-Error "Could not determine the PowerShell executable path for the current session."
        return
    }

    $argumentList = @()
    $argumentList += "-NoExit"
    if ($PSBoundParameters.ContainsKey('Command')) {
        $commandToExecute = $Command -join ' '
        $argumentList += "-Command"
        $argumentList += "& { $commandToExecute }"
    }

    try {
        Start-Process -FilePath $powerShellExecutable -Verb RunAs -ArgumentList $argumentList
    }
    catch {
        Write-Error "Failed to launch administrative PowerShell window. Error: $($_.Exception.Message)"
        Write-Warning "This usually happens if User Account Control (UAC) is disabled or if you do not have sufficient permissions to run as administrator."
    }
}
# Add a user named 'TestUser' to the Administrators group
# Add-LocalAdmin -User "TestUser"
# Function to add a specified user to the local Administrators group
function Add-LocalAdmin
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$User
    )

    Write-Host "Checking administrative privileges..."
    if (-not (Test-IsAdministrator)) {
        Write-Error "Insufficient privileges. Please run PowerShell as Administrator to use this function."
        return
    }

    $targetUser = $User # Use the specified user
    $localAdminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction SilentlyContinue

    if (-not $localAdminGroup) {
        Write-Error "The local 'Administrators' group was not found. This is unexpected."
        return
    }

    Write-Host "Target user for action: $targetUser"
    Write-Host "Action requested: Add '$targetUser' to 'Administrators' group."

    try {
        if (-not (Get-LocalGroupMember -Group $localAdminGroup | Where-Object {$_.Name -eq $targetUser})) {
            Add-LocalGroupMember -Group $localAdminGroup -Member $targetUser -ErrorAction Stop
            Write-Host "SUCCESS: '$targetUser' has been added to the 'Administrators' group."
            Write-Host "Please note that changes may require logging out and logging back in, or a system restart, to take full effect for '$targetUser'."
        } else {
            Write-Host "INFO: '$targetUser' is already a member of the 'Administrators' group."
        }
    }
    catch {
        Write-Error "An error occurred while adding user '$targetUser': $($_.Exception.Message)"
        Write-Error "Ensure the user account '$targetUser' exists and you have permissions."
    }
}

# Function to remove a specified user from the local Administrators group
# Remove a user named 'ExampleUser' from the Administrators group
# Remove-LocalAdmin -User "ExampleUser"
function Remove-LocalAdmin
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$User
    )

    Write-Host "Checking administrative privileges..."
    if (-not (Test-IsAdministrator)) {
        Write-Error "Insufficient privileges. Please run PowerShell as Administrator to use this function."
        return
    }

    $targetUser = $User # Use the specified user
    $localAdminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction SilentlyContinue

    if (-not $localAdminGroup) {
        Write-Error "The local 'Administrators' group was not found. This is unexpected."
        return
    }

    Write-Host "Target user for action: $targetUser"
    Write-Host "Action requested: Remove '$targetUser' from 'Administrators' group."

    try {
        if (Get-LocalGroupMember -Group $localAdminGroup | Where-Object {$_.Name -eq $targetUser}) {
            Remove-LocalGroupMember -Group $localAdminGroup -Member $targetUser -ErrorAction Stop
            Write-Host "SUCCESS: '$targetUser' has been removed from the 'Administrators' group."
            Write-Host "Please note that changes may require logging out and logging back in, or a system restart, to take full effect for '$targetUser'."
        } else {
            Write-Host "INFO: '$targetUser' is not a member of the 'Administrators' group."
        }
    }
    catch {
        Write-Error "An error occurred while removing user '$targetUser': $($_.Exception.Message)"
        Write-Error "Ensure the user account '$targetUser' exists and you have permissions."
    }
}

# This function checks for the existence of PowerShell ISE and starts it with admin rights.
# If file paths are provided, it opens those files in ISE; otherwise, it opens ISE without any files.
# If PowerShell ISE is not found, it provides a warning message.
# The function uses Start-Process to launch ISE with the specified files or without any files
# and runs it with elevated privileges.
# This function is useful for quickly opening PowerShell ISE with specific scripts or files
# or just starting ISE for script editing without any specific files.
function ISE {
    param(
        [Parameter(ValueFromRemainingArguments=$true)]
        [string[]]$FilePath
    )

    $isePath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"

    if (-not (Test-Path $isePath)) {
        Write-Warning "PowerShell ISE not found at '$isePath'. Ensure Windows PowerShell is installed."
        return
    }

    if ($FilePath.Count -gt 0) {
        $argList = "-File `"" + ($FilePath -join ' ') + "`""
        
        Write-Host "Opening ISE with file(s): $($FilePath -join ', ')"
        Start-Process -FilePath $isePath -Verb RunAs -ArgumentList $argList -ErrorAction Stop
    } else {
        Write-Host "Opening ISE without a specific file."
        Start-Process -FilePath $isePath -Verb RunAs -ErrorAction Stop
    }
}

function ISEAdmin {
    [CmdletBinding(DefaultParameterSetName='NoCommand')]
    param (
        [Parameter(Position=0, ValueFromRemainingArguments=$true, ParameterSetName='Command')]
        [string[]]$Command
    )

    $iseExecutable = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell_ise.exe"

    if (-not (Test-Path $iseExecutable)) {
        Write-Error "Could not locate 'powershell_ise.exe' at '$iseExecutable'. Please ensure PowerShell ISE is installed correctly on your system."
        return
    }

    $argumentList = @()

    if ($PSBoundParameters.ContainsKey('Command')) {
        $commandToExecute = $Command -join ' '
        $argumentList += "-Command"
        $argumentList += "& { $commandToExecute }"
    }

    try {
        Write-Host "Attempting to launch PowerShell ISE with administrative privileges..."

        $startProcessParams = @{
            FilePath = $iseExecutable
            Verb     = "RunAs"
        }

        if ($argumentList.Count -gt 0) {
            $startProcessParams.ArgumentList = $argumentList
        }

        Start-Process @startProcessParams
        
    }
    catch {
        Write-Error "Failed to launch administrative PowerShell ISE window. Error: $($_.Exception.Message)"
        Write-Warning "This usually happens if User Account Control (UAC) is disabled or if you do not have sufficient permissions to run as administrator."
    }
}

# Simple Function to get system uptime in a human-readable format
# This function retrieves the system uptime using WMI and formats it into a readable string.
# It calculates the difference between the current date and the last boot time of the operating system.
function HoursUptime {
    if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            $lastBootTime = $os.LastBootUpTime
        }
        catch {
            Write-Warning "Could not use Get-CimInstance. Attempting to fall back to Get-WmiObject. Error: $($_.Exception.Message)"
            try {
                $os = Get-WmiObject -Class Win32_OperatingSystem
                $lastBootTime = $os.ConvertToDateTime($os.LastBootUpTime)
            }
            catch {
                Write-Error "Failed to retrieve operating system information using either Get-CimInstance or Get-WmiObject. Error: $($_.Exception.Message)"
                return
            }
        }
    } else {
        try {
            $os = Get-WmiObject -Class Win32_OperatingSystem
            $lastBootTime = $os.ConvertToDateTime($os.LastBootUpTime)
        }
        catch {
            Write-Error "Failed to retrieve operating system information using Get-WmiObject. Error: $($_.Exception.Message)"
            return
        }
    }

    
    $uptime = (Get-Date) - $lastBootTime
    $Display = "Uptime: $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
    Write-Output $Display
}


# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin

# Admin Check and Prompt Customization
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function prompt {
    if ($isAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

# Utility Functions
function Test-CommandExists {
    param($command)
    $exists = $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
    return $exists
}

# Editor Configuration
$EDITOR = if (Test-CommandExists nvim) { 'nvim' }
          elseif (Test-CommandExists pvim) { 'pvim' }
          elseif (Test-CommandExists vim) { 'vim' }
          elseif (Test-CommandExists vi) { 'vi' }
          elseif (Test-CommandExists code) { 'code' }
          elseif (Test-CommandExists notepad++) { 'notepad++' }
          elseif (Test-CommandExists sublime_text) { 'sublime_text' }
          else { 'notepad' }
Set-Alias -Name vim -Value $EDITOR

function Edit-Profile {
    vim $PROFILE.CurrentUserAllHosts
}
function touch($file) { "" | Out-File $file -Encoding ASCII }
function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.directory)\$($_)"
    }
}

# Network Utilities
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip).Content }
function Get-PrivIP { (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -ne "Loopback Pseudo-Interface 1" }).IPAddress }
function Get-WiFiProfiles {
    # Function to retrieve Wi-Fi profiles and their passwords
    param (
        [int]$DelayInSeconds = 0
    )

    # Array to store profiles
    $Profiles = @()

    # Get Wi-Fi profiles
    $Profiles += (netsh wlan show profiles) | 
        Select-String "\:(.+)$" | 
        Foreach-Object { $_.Matches.Groups[1].Value.Trim() }

    # Retrieve Wi-Fi passwords and format the output
    $Profiles | 
        ForEach-Object {
            $SSID = $_
            (netsh wlan show profile name="$_" key=clear) |
                Select-String "Key Content\W+\:(.+)$" |
                ForEach-Object { 
                    $pass = $_.Matches.Groups[1].Value.Trim()
                    [PSCustomObject]@{
                        Wireless_Network_Name = $SSID
                        Password = $pass
                    }
                }
        } |
        Format-Table -AutoSize

    # Delay as specified
    Start-Sleep -Seconds $DelayInSeconds
}

# System Utilities
function uptime {
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Get-WmiObject win32_operatingsystem | Select-Object @{Name='LastBootUpTime'; Expression={$_.ConverttoDateTime($_.lastbootuptime)}} | Format-Table -HideTableHeaders
    } else {
        net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
    }
}

function reload-profile {
    & $profile
}

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}
function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

function df {
    get-volume
}

function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function pgrep($name) {
    Get-Process $name
}

function head {
  param($Path, $n = 10)
  Get-Content $Path -Head $n
}

function tail {
  param($Path, $n = 10)
  Get-Content $Path -Tail $n
}

# Quick File Creation
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

### Quality of Life Aliases

# Navigation Shortcuts
function docs { Set-Location -Path $HOME\Documents }
function dtop { Set-Location -Path $HOME\Desktop }
function dl { Set-Location -Path $HOME\Downloads }
function home {Set-Location -Path $HOME }
function onedrive { Set-Location -Path $HOME\OneDrive }

# Quick Access to Editing the Profile
function ep { vim $PROFILE }

# Simplified Process Management
function k9 { Stop-Process -Name $args[0] }

# Enhanced Listing
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize }

# Git Shortcuts
function gs { git status }

function ga { git add . }

function gc { param($m) git commit -m "$m" }

function gp { git push }

function g { z Github }

function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}

# Quick Access to System Information
function sysinfo { Get-ComputerInfo }

# Networking Utilities
function flushdns { Clear-DnsClientCache }

# Clipboard Utilities
function cpy { Set-Clipboard $args[0] }

function pst { Get-Clipboard }

# Enhanced PowerShell Experience
Set-PSReadLineOption -Colors @{
    Command = 'Yellow'
    Parameter = 'Green'
    String = 'DarkCyan'
}

## Final Line to set prompt
oh-my-posh init pwsh --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/cobalt2.omp.json | Invoke-Expression
if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    Invoke-Expression (& { (zoxide init powershell | Out-String) })
} else {
    Write-Host "zoxide command not found. Attempting to install via winget..."
    try {
        winget install -e --id ajeetdsouza.zoxide
        Write-Host "zoxide installed successfully. Initializing..."
        Invoke-Expression (& { (zoxide init powershell | Out-String) })
    } catch {
        Write-Error "Failed to install zoxide. Error: $_"
    }
}
