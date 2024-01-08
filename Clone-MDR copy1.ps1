#===================================================
# AlienVault Server Setup Script
# Created and maintained by Rob Emmerson <rob.emmerson@delinian.com> in Infosec
#===================================================
#===================================================
# Modified by Tom Kinnaird - Claranet
#===================================================


param(
    [Parameter(Mandatory = $true, HelpMessage = "Sensor IP is required.")]
    [string]$SensorIP
)
# Check to see if 'ReuseThread' can be used to help mitigate memory leaks
if (($ver = $host | select version).Version.Major -gt 1)  {$Host.Runspace.ThreadOptions = "ReuseThread"}

# Verify that user running script is an administrator - if not, automatically elevate to admin
$IsAdmin=[Security.Principal.WindowsIdentity]::GetCurrent()
If ((New-Object Security.Principal.WindowsPrincipal $IsAdmin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $FALSE)
{
    "`nERROR: You are NOT a local administrator.  Run this script after logging on with a local administrator account." # We are not running "as Administrator" - so relaunch as administrator
    $newProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell"; # Create a new process object that starts PowerShell
    $newProcess.Arguments = $myInvocation.MyCommand.Definition; # Specify the current script path and name as a parameter
    $newProcess.Verb = "runas"; # Indicate that the process should be elevated
    [System.Diagnostics.Process]::Start($newProcess); # Start the new process
    exit # Exit from the current, unelevated, process
}

# Ensure that TLSv1.2 is used - otherwise older OSes will default to TLSv1 and fail
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Define the variables that we need to use
$SysmonSrc = "https://github.com/oloruntolaallbert/powershell/blob/main/mdr-supporting-files-main/sysmon.zip"
$SysmonDst = "$($env:TEMP)\sysmon.zip"
$SysmonServiceName = "Sysmon64"
$SysmonConfigSrc = "https://raw.githubusercontent.com/oloruntolaallbert/powershell/main/mdr-supporting-files-main/sysmon_config_schema4_0.xml" # "https://agent-packageserver.alienvault.cloud/repo/windows/sysmon_config_schema4_0.xml"
$SysmonConfigDst = [System.IO.Path]::GetTempFileName()
$SysmonInstallDst = "$($env:USERPROFILE)\Documents\Sysmon\"
$SysmonInstallLocation = "C:\Windows\sysmon64.exe"

$NxLogSrc = "https://github.com/oloruntolaallbert/powershell/blob/main/mdr-supporting-files-main/nxlog.msi"
$NxLogDst = "$($env:TEMP)\nxlog.msi"
$NxLogServiceName = "nxlog"
$NxLogSyslogTls = $FALSE
$NxLogConfigFilePath = 'C:\Program Files\nxlog\conf\nxlog.conf'
$NxLogLogFilePath = 'C:\Program Files\nxlog\data\nxlog.log'
$NxLogLogFilePathsToRemove = @(
    'C:\Program Files\nxlog\data\configcache.dat',
    'C:\Program Files\nxlog\data\out.q',
    'C:\Program Files\nxlog\data\nxlog.log'
)

$IsAzure = $IsAws = $false
$SubscriptionId = $UsmIp = ''
$SysmonStatus = $NxLogStatus = "Unknown"
$IISStatus = $ApacheStatus = $DNSStatus = $DHCPStatus = $MSSQLServerStatus = $NPSStatus = "Not installed"
$NetlogonStatus = "Disabled"
$RegistryRootKey = "HKLM:\Software\MDR"
$RegistryApacheLocation = "ApacheLogLocation"
$RegistrySensorOverride = "SensorIpOverride"
$MDRDirectory = "C:\ProgramData\MDR"
$UpdateScriptLocation = "Update.ps1"
$UpdateScriptContents = "W05ldC5TZXJ2aWNlUG9pbnRNYW5hZ2VyXTo6U2VjdXJpdHlQcm90b2NvbCA9IFtOZXQuU2VjdXJpdHlQcm90b2NvbFR5cGVdOjpUbHMxMg0KSUVYKE5ldy1PYmplY3QgTmV0LldlYmNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHBzOi8vc2VudGluZWxjb25maWdzdG9yZS5ibG9iLmNvcmUud2luZG93cy5uZXQvZXVyb20vQ2xhcmFuZXQtTURSLnBzMT9zcD1yJnN0PTIwMjMtMTItMDNUMjA6MTI6MTJaJnNlPTIwMjUtMTItMDRUMDQ6MTI6MTJaJnNwcj1odHRwcyZzdj0yMDIyLTExLTAyJnNyPWImc2lnPVN5ODdvQmo2Wlg5bThlTGFIUnRyUWdZWWtZekQwelpUcXdTcnp5NGtMZUElM0QnKTsgVXBkYXRlLU54TG9nQ29uZmlnRmlsZQ0="
$UpdateScriptTaskName = 'MDR Update Script'

$TeamsWebhookSuccess = "https://claranet.webhook.office.com/webhookb2/82cd37f6-5167-4f0f-92f0-8fa8b76316d4@f87a7640-3b94-4bbd-b5fa-b4c15947cf56/IncomingWebhook/a11c24fb91a14de7b8b5cf37bb565657/b1e2c795-f63c-4fc1-85bf-0c7f2621c084"
$TeamsWebhookFailure = "https://claranet.webhook.office.com/webhookb2/82cd37f6-5167-4f0f-92f0-8fa8b76316d4@f87a7640-3b94-4bbd-b5fa-b4c15947cf56/IncomingWebhook/a11c24fb91a14de7b8b5cf37bb565657/b1e2c795-f63c-4fc1-85bf-0c7f2621c084"
$IconUrl = "https://github.com/oloruntolaallbert/powershell/blob/main/mdr-supporting-files-main/images/windows-server-400px-400px.png"
$LocalMachineDNSName = [Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
$LocalMachineIPAddress = [Net.Dns]::GetHostByName($env:COMPUTERNAME).AddressList[0].IPAddressToString


    # Script execution logic would go here...

 catch {
    Write-Error $_.Exception.Message
    exit
}

$WindowsDeleteOnRebootSupported = $false
try {
    # Load preferred extraction method's assembly (.NET 4.5 or later)
    Add-Type -ErrorAction Stop @"
        using System.Runtime.InteropServices;

        public class Tools
        {
            public enum MoveFileFlags
            {
                MOVEFILE_REPLACE_EXISTING = 0x00000001,
                MOVEFILE_COPY_ALLOWED = 0x00000002,
                MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004,
                MOVEFILE_WRITE_THROUGH = 0x00000008,
                MOVEFILE_CREATE_HARDLINK = 0x00000010,
                MOVEFILE_FAIL_IF_NOT_TRACKABLE = 0x00000020
            }

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, MoveFileFlags dwFlags);

            public static bool MarkFileDelete(string sourcefile)
            {
                bool brc = false;
                brc = MoveFileEx(sourcefile, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT);
                return brc;
            }
        }
"@
    $WindowsDeleteOnRebootSupported = $true
}
catch [System.Exception] {
    Write-Host "[x] Could not Add-Type for deletion on reboot" -ForegroundColor Red
    Send-FailureNotification "Function: Add-Type for deletion on reboot failed" $_.Exception.Message
}



#===================================================
# Sysmon Installation
#===================================================

function Install-SysmonMonitor() {
    Write-Host "`n[-] Installation: Sysmon64`n" -ForegroundColor Magenta
    
    if (Download-File $SysmonConfigSrc $SysmonConfigDst) {
        Write-Host "[+] Sysmon configuration file downloaded successfully`n" -ForegroundColor Green
    } else {
        Write-Host "[x] Sysmon configuration file failed to download, using base sysmon config`n" -ForegroundColor Red
        Send-FailureNotification "Sysmon configuration file failed to download"
    }
    
    if (Download-File $SysmonSrc $SysmonDst) {
        Write-Host "[+] Sysmon downloaded successfully`n" -ForegroundColor Green
        
        # Remove existing versions of Sysmon to ensure we are using the latest one
        Remove-CurrentSysmon 'Sysmon'
        Remove-CurrentSysmon 'Sysmon64'
        
        Install-Sysmon
        Write-Host "[+] Sysmon installed!" -ForegroundColor Green
    } else {
        Write-Host "[x] Failed to download Sysmon`n" -ForegroundColor Red
        Send-FailureNotification "Failed to download Sysmon"
    }

    Write-Host "`n[-] Removing unneeded Sysmon installation files"
    Remove-Files -Files $SysmonInstallDst,$SysmonDst,$SysmonConfigDst
    Write-Host "[+] All unneeded Sysmon files removed" -ForegroundColor Green
}

function Install-Sysmon() {
    Write-Host "[-] Creating Sysmon target path: '$SysmonInstallDst'"
    [void](New-Item -ItemType Directory -Force -Path $SysmonInstallDst) # Suppress output, but not errors

    if (-not (Test-Path -Path $SysmonInstallDst)) {
        Write-Host "[x] Skipping Sysmon... Destination path '$SysmonInstallDst' does not exist." -ForegroundColor Red
    }
    else {
        # Unzip Sysmon
        Unblock-File -Path $SysmonDst
        Write-Host "[-] Uncompressing the zip file to: '$SysmonInstallDst'"

        $FoundExtractionAssembly = 0
        try {
            # Load preferred extraction method's assembly (.NET 4.5 or later)
            Add-Type -As System.IO.Compression.FileSystem -ErrorAction Stop
            $FoundExtractionAssembly = 1
        }
        catch [System.Exception] {
            Write-Host "[x] Could not Add-Type for System.IO.Compression.FileSystem" -ForegroundColor Red
            Send-FailureNotification "Function: Add-Type for System.IO.Compression.FileSystem failed" $_.Exception.Message
        }

        if ($FoundExtractionAssembly) {
            [IO.Compression.ZipFile]::ExtractToDirectory($SysmonDst, $SysmonInstallDst)
        }
        else {
            # Fall-back method, may fail in sessions lacking access to interactive shell
            $continue_flag = 1
            try {
                $shell_app = New-Object -COMObject "Shell.Application"
            }
            catch {
                Write-Host "[x] Could not create Shell.Application object" -ForegroundColor Red
                Send-FailureNotification "Could not create Shell.Application object" $_.Exception.Message
                $continue_flag = 0
            }
            if ($continue_flag) {
                $zip_file = $shell_app.namespace($SysmonDst)
                $destination = $shell_app.namespace($SysmonInstallDst)
                if ($destination -ne $null) {
                    $destination.Copyhere($zip_file.items(), 0x10)
                }
            }
        }
    }

    $SysmonArgs = "-accepteula -i " # Default Sysmon install

    # If a custom Syslog configuration file exists, use it
    if (Test-Path -Path $SysmonConfigDst -PathType Leaf) {
        Write-Host "[-] Sysmon configuration file to use $SysmonConfigDst"
        $SysmonArgs += $SysmonConfigDst
    }
    else {
        Write-Host "[-] Not using an additional Sysmon configuration file"
    }

    Write-Host "[-] Installing Sysmon with arguments: '$SysmonArgs'"
    Start-Process -Wait -NoNewWindow "$SysmonInstallDst\sysmon64" -ArgumentList $SysmonArgs
}


function Remove-Files() {
    [CmdletBinding()]
    Param (
       [Parameter(Mandatory=$True)]
       [String[]]$Files
    )

    $Files | ForEach-Object {
        Write-Host "[-] Attempting to remove: $_"
        if (Test-Path -Path $_) { try { Remove-Item $_ -Force -Recurse -ErrorAction SilentlyContinue } catch {} }
        if (Test-Path -Path $_) {
            if ($WindowsDeleteOnRebootSupported) {

                # Check if the current 'file' is a directory or not, if it is, we need to mark each file inside the directory for deletion otherwise the folder will not be deleted
                if (Test-Path -Path $_ -PathType Container) {
                    $currentDir = $_
                    Get-ChildItem $_ | ForEach-Object {
                        $fullFilePath = $currentDir + $_
                        if ([Tools]::MarkFileDelete($fullFilePath)) {
                            Write-Host "[-] Cannot remove: '$fullFilePath' now. This file has been marked for deletion on reboot" # Successfully marked file for deletion on reboot
                        }
                    }
                }

                # Delete files next time Windows reboots
                if ([Tools]::MarkFileDelete($_)) {
                    Write-Host "[-] Cannot remove: '$_' now. This file has been marked for deletion on reboot" # Successfully marked file for deletion on reboot
                }
                else {
                    Write-Host "[x] Error: Unable to mark '$_' for deletion on reboot, please manually cleanup these file(s)" -ForegroundColor Red
                }
            }
            else {
                # If 'delete on reboot' is not supported, ask the user to delete these files manually
                Write-Host "[x] Error: Unable to delete '$_', please manually cleanup these file(s)" -ForegroundColor Red
            }
        }
        else {
            # No file(s) detected, show success message
            Write-Host "[-] '$_' removed successfully!"
        }
    }
}



#===================================================
# NxLog Installation
#===================================================

function Install-NxLog() {
    Write-Host "`n[-] Installation: NxLog`n" -ForegroundColor Magenta
    if (Download-File $NxLogSrc $NxLogDst) {
        try {
            Write-Host "[+] NxLog installation file downloaded`n" -ForegroundColor Green

            $NxLogInstallArgs = "/i $NxLogDst /quiet /qn /norestart"
            Write-Host "[-] Installing NxLog with arguments: 'msiexec.exe $NxLogInstallArgs'"
            Start-Process -Wait msiexec.exe -NoNewWindow -ArgumentList $NxLogInstallArgs -ErrorAction Stop
            Write-Host "[+] NxLog installed!" -ForegroundColor Green
        }
        catch {
            Write-Host "[x] NxLog Installation failed with message: $($_.Exception.Message)" -ForegroundColor Red
            Send-FailureNotification "NxLog Installation failed" $_.Exception.Message
        }
        finally {
            Write-Host "`n[-] Removing unneeded NxLog installation files"
            Remove-Files -Files $NxLogDst
            Write-Host "[+] All unneeded NxLog files removed" -ForegroundColor Green
        }
    }

    if (Check-ServiceExists $NxLogServiceName) {
        # Create the NxLog configuration file based on what roles are installed on the server
        Write-NxLogConfigFile
        
        


        Start-NxLog
    }
    else {
        Write-Host "[x] NxLog Configuration failed as NxLog is not installed" -ForegroundColor Red
    }
}

function Start-NxLog() {
    # Attempt to restart the 'nxlog' service. This usually fails as it doesn't terminate gracefully, so we wait a couple of seconds and then attempt to start any stopped services
    Restart-Service $NxLogServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 4
    if ((Get-Service $NxLogServiceName).status -ne "Running") {
        Start-Service $NxLogServiceName

        Start-Sleep -Seconds 2
        if ((Get-Service $NxLogServiceName).status -ne "Running") {
            Send-FailureNotification "Unable to start NxLog - Please Investigate!"
        }
    }
}

function Stop-NxLog {
    # Attempt to stop the 'nxlog' service so we can tidy up the logs
    Stop-Service $NxLogServiceName
    $sleep=0
    $s="Running"
    do {
       $sleep++
       start-sleep 1
       $s=(get-service $NxLogServiceName).status
    } while (($s -ne "Stopped") -and ($sleep -le 20))
}

function Write-NxLogConfigFile()
{
    $conf = Build-NxLogConfig
    Write-Host "" # Blank line for log formatting purposes
    Remove-Files -Files $NxLogConfigFilePath
    Add-Content $NxLogConfigFilePath $conf
    Write-Host "[+] New NxLog configuration file written to: '$NxLogConfigFilePath'`n" -ForegroundColor Green
}

function Update-NxLogConfigFile()
{
    Import-ExtraFunctions
    Initialize-SubscriptionDetection

    # Create new config file
    $conf = Build-NxLogConfig
    $tmpFile = New-TemporaryFile
    Write-Host "[*] Temporary file created: $tmpFile" -ForegroundColor Yellow
    Add-Content $tmpFile $conf


    # Compare new config to existing
    $tmpHash = (Get-FileHash -Path $tmpFile -Algorithm SHA256).Hash
    Write-Host "`n[+] Hash for temporary file: $tmpHash" -ForegroundColor Green

    $realHash = (Get-FileHash -Path $NxLogConfigFilePath -Algorithm SHA256).Hash
    Write-Host "[+] Hash for real file:      $realHash" -ForegroundColor Green

    if ($tmpHash -ne $realHash) {
        Write-Host "`nFiles don't match, updating..."
        Remove-Files -Files $NxLogConfigFilePath
        Add-Content $NxLogConfigFilePath $conf
        Write-Host "[+] New NxLog configuration file written to: '$NxLogConfigFilePath'`n" -ForegroundColor Green

        # Ensure NxLog is started
        Start-NxLog
    } else {
        Write-Host "`n[+] No update required`n" -ForegroundColor Green
    }

    # Cleanup
    Remove-Files -Files $tmpFile

    # Sysmon Update Check
    $SysmonDesiredVersion = "14.16"

    if (Test-Path $SysmonInstallLocation) {
        $version = (Get-Item $SysmonInstallLocation).VersionInfo.FileVersion
        if ($version -ne $SysmonDesiredVersion) {
            Write-Host "`nSysmon version is not $SysmonDesiredVersion. Updating..."
            Install-SysmonMonitor
        }
    }

    # NxLog Log Size Check
    if (Test-Path $NxLogLogFilePath) {
        # Get the file size
        $fileSize = (Get-Item $NxLogLogFilePath).length

        # Check if file size exceeds 1GB
        if ($fileSize -gt 1GB) {
            $last6Lines = (Get-Item -Path $NxLogLogFilePath | Get-Content -Tail 6) -join "|"
            Send-FailureNotification "NxLog Log File has exceeded 1GB, size: $(Get-PrettyFileSize -Value $fileSize)" $last6Lines

            Write-Host "`nNxLog log file has exceeded 1GB and will be deleted..."
            Stop-NxLog
            Remove-Files -Files $NxLogLogFilePathsToRemove
            Start-NxLog
            Write-Host "`n[+] NxLog log file has been removed and the process has been restarted" -ForegroundColor Green
        }
    }

    # Update file check
    Invoke-UpdateScriptCheck
}

function Test-RegistryValue {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Name
    )

    try {
        $regkey = Get-ItemProperty -ErrorAction Stop -Path $Path
        if ([string]::IsNullOrEmpty($regkey)) { return $false }

        $regkey | Select-Object -ExpandProperty $Name -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Get-RegistryValue {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Name
    )

    try {
        return Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Name -ErrorAction Stop
    } catch {
        return ''
    }
}

function Add-RegistryValue {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Name,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Value
    )

    try {
        # Create a new key if it doesn't already exist
        if (-not (Test-Path -Path $Path -PathType Container)) {
            $mdrKey = $Path.Split('\')[-1]
            $limit = $Path.IndexOf($mdrKey) - 1
            $parentPath = $Path.Substring(0, $limit)

            Push-Location -Path $parentPath
            New-Item -Name $mdrKey -Force | Out-Null
            Pop-Location
        }

        # Create new items with values
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
        Write-Host "[+] Added '$Name' to registry key '$Path' with value: '$Value'" -ForegroundColor Green
    } catch {}
}

function Get-PrettyFileSize {
    param(
        [Int64]$Value,
        [int]$DecimalPlaces = 1
    )

    if ($DecimalPlaces -lt 0) { throw "DecimalPlaces must be non-negative" }
    if ($Value -lt 0) { return "-" + (SizeSuffix -Value (-$Value) -DecimalPlaces $DecimalPlaces) }
    if ($Value -eq 0) { return "{0:n$DecimalPlaces} bytes" -f 0 }

    $mag = [Math]::Floor([Math]::Log($Value, 1024))
    $adjustedSize = $Value / [Math]::Pow(2, $mag * 10)

    if ([Math]::Round($adjustedSize, $DecimalPlaces) -ge 1000) {
        $mag += 1
        $adjustedSize /= 1024
    }

    $SizeSuffixes = @("bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    return "{0:n$DecimalPlaces} {1}" -f $adjustedSize, $SizeSuffixes[$mag]
}

function Build-NxLogConfig()
{
    Set-Variable -Name "UsmIp" -Value (Get-USMIPAddress) -Scope Script
    Set-Variable -Name "NxLogSyslogTls" -Value $false -Scope Script
   
    
    if ($NxLogSyslogTls) {
        $Config = $NxLogDefaultTlsConfiguration.Replace("CHANGEME_IPADDRESS", "$UsmIp")
    } else {
        $Config = $NxLogDefaultConfiguration.Replace("CHANGEME_IPADDRESS", "$UsmIp")
    }

    if ((Get-WmiObject -Class Win32_OperatingSystem).Caption -like "*Server 2012*") {
        $Config = $Config -replace '.*<Select Path="Microsoft-Windows-Windows Defender/Operational">\*<\/Select>\\.*\r?\n', ""
    }

    Write-Host "`n[-] Checking server for installed roles"

    if (Check-ServerRoleInstalled("IIS-WebServer")) {
        Set-Variable -Name "IISStatus" -Value "Installed" -Scope Script
        $IISConfig = Get-IISLoggingConfig
        $Config = -join $Config, $IISConfig
    }

    # Check whether the 'ApacheLogFile' parameter was passed as an argument, and if it was, import the Apache config
    if (Test-RegistryValue -Path $RegistryRootKey -Name $RegistryApacheLocation) {
        $ApacheLogLocation = (Get-RegistryValue -Path $RegistryRootKey -Name $RegistryApacheLocation)
        Write-Host "[+] Apache log file provided, configuring logging..." -ForegroundColor Green
        $Config = -join $Config, $NxLogApacheConfiguration.replace('CHANGEME_APACHE_ACCESSLOG', $ApacheLogLocation)
    }
    else {
        Write-Host "[-] Apache log file not provided" -ForegroundColor Red
    }

    # # Check whether Windows Firewall is enabled or not and add logging for it
    # $firewallNetwork = "Domain"
    # if ((Get-NetFirewallProfile -Name $firewallNetwork).Enabled) {
    #     Write-Host "[+] Windows Firewall is enabled for: $firewallNetwork" -ForegroundColor Green
    #     $FirewallConfig = Get-FirewallLoggingConfig
    #     $Config = -join $Config, $FirewallConfig
    # }
    # else {
    #     Write-Host "[-] Windows Firewall is not enabled for: $firewallNetwork"
    # }

    # Checks whether Windows DHCP is installed & enabled, and adds logging for it
    if (Check-ServerRoleInstalled("DHCPServer")) {
        # Check whether DHCP is actually enabled and serving
        if ((Get-DhcpServerSetting).IsAuthorized) {
            Set-Variable -Name "DHCPStatus" -Value "Installed" -Scope Script
            $Config = -join $Config, $NxLogDHCPConfiguration
        }
    }
    
    # Checks whether Windows DNS is installed & enabled, and adds logging for it
    if (Check-ServerRoleInstalled("DNS-Server-Full-Role")) {
        Set-Variable -Name "DNSStatus" -Value "Installed" -Scope Script
        $DNSConfig = Get-DNSLoggingConfig
        $Config = -join $Config, $DNSConfig
    }

    # Check for Netlogon debugging
    if (Test-Path -Path "C:\\Windows\\debug\\netlogon.log") {
        Set-Variable -Name "NetlogonStatus" -Value "Enabled" -Scope Script
        Write-Host "[+] Netlogon debugging is enabled, configuring logging..." -ForegroundColor Green
        $Config = -join $Config, $NxLogNetlogonConfiguration
    }
    else {
        Write-Host "[-] Netlogon debugging not detected" -ForegroundColor Red
    }

    # Check for SQL Server
    if (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
        Set-Variable -Name "MSSQLServerStatus" -Value "Installed" -Scope Script
        Write-Host "[+] MS SQL Server is installed, configuring logging..." -ForegroundColor Green
        $Config = -join $Config, $NxLogMSSQLConfiguration
    }
    else {
        Write-Host "[-] MS SQL Server not detected" -ForegroundColor Red
    }

    # Check for NPS
    if (Check-ServerRoleInstalled("NPSMMC")) {
        Set-Variable -Name "NPSStatus" -Value "Installed" -Scope Script
        Write-Host "[+] NPS is installed, configuring logging..." -ForegroundColor Green
        $Config = -join $Config, $NxLogNPSConfiguration
    }
    else {
        Write-Host "[-] NPS not detected" -ForegroundColor Red
    }

    return $Config
}



#===================================================
# Individual Service Configuration
#===================================================

function Get-IISLoggingConfig()
{
    # Required module for setting advanced logging options
    Import-Module WebAdministration

    # Default IIS logging values, should work for all IIS versions
    $IISLoggingValues = 'Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,TimeTaken,ServerPort,UserAgent,Referer,HttpSubStatus'
    $NxLogIISLoggingFields = '$date, $time, $s_ip, $cs_method, $cs_uri_stem, $cs_uri_query, $s_port, $cs_username, $c_ip, $cs_User_Agent, $cs_Referer, $sc_status, $sc_substatus, $sc_win32_status, $time_taken'
    $NxLogIISLoggingFieldTypes = 'string, string, string, string, string, string, integer, string, string, string, string, integer, integer, integer, integer'
    $NxLogIISLoggingDirectories = ''

    # Check if enhanced logging can be enabled or not - IIS 8.5+
    $IISVersion = $(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp\).setupstring
    $IISVersion7 = ($IISVersion -like '*IIS 7.5*')
    $IISVersion8Plus = ($IISVersion -like '*IIS 8*' -or $IISVersion -like '*IIS 10*')

    # A variable to store any custom fields in for reporting
    $headerNamesToReport = @()

    if($IISVersion7) {
        Write-Host "[+] IIS 7.5 detected, enabling additional logging..." -ForegroundColor Green

        # Override the default variables
        $IISLoggingValues = 'Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Referer,Host,HttpSubStatus'
        $NxLogIISLoggingFields = '$date, $time, $s_ip, $cs_method, $cs_uri_stem, $cs_uri_query, $s_port, $cs_username, $c_ip, $cs_User_Agent, $cs_Referer, $cs_host, $sc_status, $sc_substatus, $sc_win32_status, $sc_bytes, $cs_bytes, $time_taken'
        $NxLogIISLoggingFieldTypes = 'string, string, string, string, string, string, integer, string, string, string, string, string, integer, integer, integer, integer, integer, integer'
    }
    elseif($IISVersion8Plus) {
        Write-Host "[+] IIS 8+ detected, enabling additional logging..." -ForegroundColor Green

        # Adds the 'X-Forwarded-For' header to the default web site + for any new sites
        $SiteDefaultLogFileCustom = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -Name 'Collection'
        if ($SiteDefaultLogFileCustom.logFieldName -notMatch 'x-forwarded-for')
        {
            Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='x-forwarded-for';sourceName='X-Forwarded-For';sourceType='RequestHeader'}
        }

        if ($SiteDefaultLogFileCustom.logFieldName -match 'c_realIP')
        {
            Write-Host "Found c_realIP header, removing..."
            Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -AtElement @{logFieldName='c_realIP'}
        }

        # Find any custom headers that we didn't set and add these to a collection for reporting later via MS Teams
        foreach ($header in $($SiteDefaultLogFileCustom | Where-Object { $_.logFieldName -ne 'x-forwarded-for' })) {
            $headerNamesToReport += "Default: { Name: '$($header.logFieldName)', Source: '$($header.sourceName)', Type: '$($header.sourceType)' }"
        }
        
        # Override the default variables
        $IISLoggingValues = 'Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Referer,Host,HttpSubStatus'
        $NxLogIISLoggingFields = '$date, $time, $s_ip, $cs_method, $cs_uri_stem, $cs_uri_query, $s_port, $cs_username, $c_ip, $cs_User_Agent, $cs_Referer, $cs_host, $sc_status, $sc_substatus, $sc_win32_status, $sc_bytes, $cs_bytes, $time_taken, $x_forwarded_for'
        $NxLogIISLoggingFieldTypes = 'string, string, string, string, string, string, integer, string, string, string, string, string, integer, integer, integer, integer, integer, integer, string'
    }
    else {
        Write-Host "[-] Unknown IIS version, using default configuration"
    }

    # Check to see if each website has the custom field added to it's logging properties
    Get-ChildItem -Path IIS:\Sites | ForEach-Object {
        $WebsiteName = $_.name
        Write-Host "[+] IIS Website: $WebsiteName, setting configuration..." -ForegroundColor Green

        if ($IISVersion8Plus) {
            $SiteLogFileCustom = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='$WebsiteName']/logFile/customFields" -Name 'Collection'
            if ($SiteLogFileCustom.logFieldName -notMatch 'x-forwarded-for') {
                Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='$WebsiteName']/logFile/customFields" -name "." -value @{logFieldName='x-forwarded-for';sourceName='X-Forwarded-For';sourceType='RequestHeader'} # Add the 'X-Forwarded-For' header to the logs for any site that doesn't have it set already
            }
            if ($SiteLogFileCustom.logFieldName -match 'c_realIP')
            {
                Write-Host "Found c_realIP header, removing..."
                Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='$WebsiteName']/logFile/customFields" -name "." -AtElement @{logFieldName='c_realIP'}
            }
            
            # Find any custom headers that we didn't set and add these to a collection for reporting later via MS Teams
            foreach ($header in $($SiteLogFileCustom | Where-Object { $_.logFieldName -ne 'x-forwarded-for' })) {
                $headerNamesToReport += "$($WebsiteName): { Name: '$($header.logFieldName)', Source: '$($header.sourceName)', Type: '$($header.sourceType)' }"
            }
        }
        
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='$WebsiteName']/logFile" -name "logExtFileFlags" -value $IISLoggingValues # Sets the logging values on the individual IIS site object

        # IIS - Check if the logs directory exists, if it does, output it in the configuration file
        $LogDir=$($_.logFile.directory.replace("%SystemDrive%",$env:SystemDrive))
        if (Test-Path -Path "$LogDir\W3SVC$($_.id)" -PathType Container) {
            $NxLogIISLoggingDirectories += "File '$LogDir\W3SVC$($_.id)\*.log'`r`n"
        }
    }

    # Report any custom headers to MS Teams - TODO: change this to go to Teams
    if ($headerNamesToReport.Count -gt 0) {
        Send-FailureNotification 'IIS Custom Headers' $($headerNamesToReport -join "`n")
    }

    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/log/centralW3CLogFile" -name "logExtFileFlags" -value $IISLoggingValues # Sets the logging values on the IIS server object    
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logExtFileFlags" -value $IISLoggingValues # Sets the logging values on the IIS default site object for any new sites that are created

    # Add IIS configuration to NxLog
    $IISConfig = $NxLogIISConfiguration.replace('CHANGEME_NXLOG_FIELDS', $NxLogIISLoggingFields)
    $IISConfig = $IISConfig.replace('CHANGEME_NXLOG_FIELDTYPES', $NxLogIISLoggingFieldTypes)
    $IISConfig = $IISConfig.replace('CHANGEME_NXLOG_IIS_LOGGING_DIRECTORIES', $NxLogIISLoggingDirectories)

    return $IISConfig
}

function Get-FirewallLoggingConfig()
{
    # Configure the logging to be 8192 bytes, and include both allowed and blocked traffic
    Set-NetFirewallProfile -name Domain -LogMaxSizeKilobytes 8192 -LogAllowed true -LogBlocked true

    # Get the location of the firewall log
    $LogFilename = (Get-NetFirewallProfile -Name 'Domain').LogFileName
    $LogFilename = [System.Environment]::ExpandEnvironmentVariables($LogFilename)
    $LogFilename = $LogFilename.Replace("\", "\\")

    $FirewallConfig = $NxLogFirewallConfiguration
    if (-not [string]::IsNullOrEmpty($LogFilename)) {
        $FirewallConfig = $FirewallConfig.replace('CHANGEME_WINDOWS_FIREWALL', $LogFilename)
    }
    else {
        $FirewallConfig = $FirewallConfig.replace('CHANGEME_WINDOWS_FIREWALL', "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log") # Set the default log location if one is not specified
    }

    return $FirewallConfig
}

function Get-DNSLoggingConfig()
{
    $LogFilePath = "C:\\Windows\\system32\\dns\\dns.log" # Default log path

    # Enable DNS logging, check whether a log
    if ((Get-DnsServerDiagnostics).EnableLoggingToFile) {
        $LogFilePathTmp = (Get-DnsServerDiagnostics).LogFilePath
        if (-not [string]::IsNullOrEmpty($LogFilePathTmp)) {
            Write-Host "[+] DNS: Using existing log file: $LogFilePathTmp" -ForegroundColor Green
            $LogFilePath = $LogFilePathTmp
        }
    }

    # Configure the DNS server to log all required fields for analysis and limit it to 1GB
    Set-DnsServerDiagnostics -LogFilePath $LogFilePath -Queries $true -Answers $true -Notifications $true -Update $true -QuestionTransactions $true -UnmatchedResponse $false -SendPackets $true -ReceivePackets $true -TcpPackets $true -UdpPackets $true -FullPackets $false -EnableLoggingToFile $true -EnableLogFileRollover $false -MaxMBFileSize 1000000000

    return $NxLogDNSConfiguration.Replace("CHANGEME_DNS", $LogFilePath)
}



#===================================================
# Helper Functions
#===================================================

function Get-IsInAzure()
{
    try {
        $MetaDataObject = Invoke-RestMethod -Headers @{"Metadata"="true"} -DisableKeepAlive -UseBasicParsing -TimeoutSec 5 -Method GET -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        return ($MetaDataObject.compute.azEnvironment -eq "AzurePublicCloud")
    }
    catch {
        if ($_ -like "*UseBasicParsing*") {
            try {
                $MetaDataObject = Invoke-RestMethod -Headers @{"Metadata"="true"} -DisableKeepAlive -TimeoutSec 5 -Method GET -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
                return ($MetaDataObject.compute.azEnvironment -eq "AzurePublicCloud")
             }
             catch {}
        }
    }

    return $false
}

function Get-AzureSubscriptionId()
{
    try {
        $MetaDataObject = Invoke-RestMethod -Headers @{"Metadata"="true"} -DisableKeepAlive -UseBasicParsing -TimeoutSec 5 -Method GET -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        return $MetaDataObject.compute.subscriptionId
    }
    catch {
        if ($_ -like "*UseBasicParsing*") {
            try {
                $MetaDataObject = Invoke-RestMethod -Headers @{"Metadata"="true"} -DisableKeepAlive -TimeoutSec 5 -Method GET -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
                return $MetaDataObject.compute.subscriptionId
             }
             catch {}
        }
    }

    return ''
}

function Get-IsInAWS()
{
    try {
        $MetaDataObject = Invoke-RestMethod -DisableKeepAlive -UseBasicParsing -TimeoutSec 5 -Method GET -Uri "http://169.254.169.254/latest/meta-data/ami-id"
        return (-not [string]::IsNullOrEmpty($MetaDataObject))
    }
    catch {
        if ($_ -like "*UseBasicParsing*") {
           try {
                $MetaDataObject = Invoke-RestMethod -DisableKeepAlive -TimeoutSec 5 -Method GET -Uri "http://169.254.169.254/latest/meta-data/ami-id"
                return (-not [string]::IsNullOrEmpty($MetaDataObject))
            }
            catch {}
        }
    }

    return $false
}

function Get-AwsSubscriptionId()
{
    try {
        $MetaDataObject = Invoke-RestMethod -DisableKeepAlive -UseBasicParsing -TimeoutSec 5 -Method GET -Uri "http://169.254.169.254/latest/dynamic/instance-identity/document" 
        return $MetaDataObject.accountId
    }
    catch {
        if ($_ -like "*UseBasicParsing*") {
            try {
                $MetaDataObject = Invoke-RestMethod -DisableKeepAlive -TimeoutSec 5 -Method GET -Uri "http://169.254.169.254/latest/dynamic/instance-identity/document" 
                return $MetaDataObject.accountId
             }
             catch {}
        }
    }

    return ''
}

function Get-AllIPAddresses()
{
    $ips = ''
    [Net.Dns]::GetHostByName($env:COMPUTERNAME).AddressList | ForEach-Object {
        $ips += "$_, "
    }
    return $ips -replace ".{2}$"
}

function Get-TeamsUSMButtonsForAllIPs()
{
    $buttons = [System.Collections.ArrayList]@()
    [Net.Dns]::GetHostByName($env:COMPUTERNAME).AddressList | ForEach-Object {
        $buttons.Add(
            [Ordered]@{
                "type"  = "Action.OpenUrl"
                "title" = "See Events for $_"
                "url"   = $AlienVaultUrlTemplate.Replace("CHANGEME_IPADDRESS", "$_")
            }
        ) | Out-Null
    }
    return $buttons
}

function Check-ServerRoleInstalled($serverRole)
{
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $serverRole -ErrorAction SilentlyContinue
        if ($feature.State -eq "Enabled") {
            Write-Host "[+] $serverRole is installed, configuring logging..." -ForegroundColor Green
            return $true
        }
    }
    catch {}

    Write-Host "[-] $serverRole Not Detected" -ForegroundColor Red
    return $false
}

function Check-ServiceExists($serviceName){
    return (Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Length -gt 0
}

function Check-ServiceRunning($serviceName) {
    return (Get-ServiceStatus $serviceName) -eq "Running"
}

function Get-ServiceStatus($serviceName) {
    try {
        return (Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status.ToString()
    }
    catch {
        return 'Not Found'
    }
}

function Get-ServicePath($serviceName) {
    try {
        return (Get-WmiObject win32_service | Where-Object -Property Name -eq "$serviceName").PathName
    }
    catch {
        return ''
    }
}

function CheckRunningServices($serviceName) {
    if (Check-ServiceExists $serviceName) {
        if (Check-ServiceRunning $serviceName) {
            Write-Host "[+] $serviceName is running!" -ForegroundColor Green
        }
    }
}

function Remove-CurrentSysmon($serviceName) {
    if (Check-ServiceExists $serviceName) {
        Write-Host "[-] Found existing '$serviceName' service, removing..."
        $path = Get-ServicePath $serviceName
        if (![string]::IsNullOrEmpty($path)) {
            Start-Process -Wait -NoNewWindow "$path" -ArgumentList "/u"
            Write-Host "[+] Service: '$serviceName' removed`n" -ForegroundColor Green
        }
    }
}

function Download-File($src, $dst) {
    Write-Host "[-] Downloading '$src' to '$dst'"
    if (Test-Path -Path $dst -PathType Leaf) { Remove-Files -Files $dst } # Remove any existing file

    $retryCount = 0
    $maxRetries = 10
    $pauseDuration = 2

    while ($true) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -UseBasicParsing $src -OutFile $dst
        }
        catch {
            Write-Host "[-] Download-File Error Code: " $_.Exception.Response.StatusCode.value__
            Write-Host "[-] Download-File Error Description:" $_.Exception.Response.StatusDescription
  
            if($_.ErrorDetails.Message){
                Write-Host "[-] Download-File Inner Error: $_.ErrorDetails.Message"
            }
        }

        if (Test-Path -Path $dst -PathType Leaf) {
            Write-Host "[-] $dst downloaded successfully"
            return $true
        }
        elseif($retryCount -ge $maxRetries) {
            Write-Host "[x] Retried $retryCount, not going to retry anymore" -ForegroundColor Red
            return $false
        }
        else {
            $retryCount += 1
            Write-Host "[-] Download-File retry attempt $retryCount after a $pauseDuration second pause..."
            Start-Sleep -Seconds $pauseDuration
        }
    }
}

function Get-ExecutionDate()
{
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ssZ")
}

function Get-EnvironmentInformation()
{
    $EnvironmentInfo = ""
    if ($IsAzure) {
        $EnvironmentInfo += "_Azure Sub: $($SubName)_"
    } elseif ($IsAws) {
        $EnvironmentInfo += "_AWS Sub: $($SubName)_"
    } else {
        $EnvironmentInfo += "_Non-Cloud Resource_"
    }
    return $EnvironmentInfo
}


function Import-ExtraFunctions()
{
    $currentVersion = [Version]$PSVersionTable.PSVersion

    if ($currentVersion -lt [Version]"5.0") {
        function script:New-TemporaryFile {
            $tempDirectory = [System.IO.Path]::GetTempPath()
            $randomFileName = [System.IO.Path]::GetRandomFileName()
            $tempFilePath = Join-Path -Path $tempDirectory -ChildPath $randomFileName
            $tempFilePath += ".tmp"

            if (-not (Test-Path -Path $tempFilePath)) {
                $null = New-Item -ItemType "File" -Path $tempFilePath -Force
            }

            return $tempFilePath
        }
    }

    if ($currentVersion -lt [Version]"4.0") {
        function script:Get-FileHash {
            [CmdletBinding()]
            Param (
            [Parameter(Mandatory=$True)]
            [String[]]$Path,
        
            [Parameter()]
                [string]
                [ValidateSet("MACTripleDES", "MD5", "RIPEMD160", "SHA1", "SHA256", "SHA384", "SHA512")]
                $Algorithm = "SHA256"
            )
        
            try
            {
                $FullPath = Resolve-Path -Path $Path -ErrorAction Stop
                $InputObject = [System.IO.File]::OpenRead($FullPath)
            
                if($InputObject.GetType() -eq [Byte[]] -or $InputObject.GetType().BaseType -eq [System.IO.Stream])
                {
                    # Construct the strongly-typed crypto object
                    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
        
                    # Compute file-hash using the crypto object
                    [Byte[]] $computedHash = $Hasher.ComputeHash($InputObject)
                    [string] $hash = [BitConverter]::ToString($computedHash) -replace '-',''
        
                    $retVal = New-Object -TypeName psobject -Property @{
                        Algorithm = $Algorithm.ToUpperInvariant()
                        Hash = $hash
                    }
                }
            }
            catch
            {
                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $null
                }
            }

            return $retVal
        }
    }
}



#===================================================
# NxLog Configuration File Snippets
#===================================================

$NxLogDefaultConfiguration = @'
#
# Automatic NxLog Configuration Generator for converting and sending logs to AlienVault USM.
#
# Written by: Rob Emmerson
# Version: 1.0
#

define ROOT C:\Program Files\nxlog
define OUTPUT_DESTINATION_ADDRESS CHANGEME_IPADDRESS
define OUTPUT_DESTINATION_PORT 601

Moduledir %ROOT%\modules
CacheDir %ROOT%\data
Pidfile %ROOT%\data\nxlog.pid
SpoolDir %ROOT%\data
LogFile %ROOT%\data\nxlog.log


<Extension json>
    Module      xm_json
</Extension>

<Extension syslog>
    Module      xm_syslog
</Extension>

<Input internal>
    Module      im_internal
</Input>

<Input eventlog>
    Module  im_msvistalog
    Query   <QueryList>\
                <Query Id="0">\
                    <Select Path="Application">*</Select>\
                    <Select Path="System">*</Select>\
                    <Select Path="Security">*</Select>\
                    <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>\
                    <Select Path="Microsoft-Windows-PowerShell/Operational">*</Select>\
                    <Select Path="Microsoft-Windows-Windows Defender/Operational">*</Select>\
                </Query>\
            </QueryList>
    Exec if ($EventID == 5156) OR ($EventID == 5158) drop();
</Input>

<Output out>
    Module om_tcp
    Host        %OUTPUT_DESTINATION_ADDRESS%
    Port        %OUTPUT_DESTINATION_PORT%
    Exec        $EventTime = integer($EventTime) / 1000000;
    Exec        $EventReceivedTime = integer($EventReceivedTime) / 1000000;
    Exec        $Message = to_json(); to_syslog_bsd();
</Output>

<Route 1>
Path eventlog, internal => out
</Route>

'@

$NxLogDefaultTlsConfiguration = @'
#
# Automatic NxLog Configuration Generator for converting and sending logs to AlienVault USM.
#
# Written by: Rob Emmerson
# Version: 1.0
#

define ROOT C:\Program Files\nxlog
define OUTPUT_DESTINATION_ADDRESS CHANGEME_IPADDRESS
define OUTPUT_DESTINATION_PORT 6514

define CERTDIR %ROOT%\cert

Moduledir %ROOT%\modules
CacheDir %ROOT%\data
Pidfile %ROOT%\data\nxlog.pid
SpoolDir %ROOT%\data
LogFile %ROOT%\data\nxlog.log


<Extension json>
    Module      xm_json
</Extension>

<Extension syslog>
    Module      xm_syslog
</Extension>

<Input internal>
    Module      im_internal
</Input>

<Input eventlog>
    Module  im_msvistalog
    Query   <QueryList>\
                <Query Id="0">\
                    <Select Path="Application">*</Select>\
                    <Select Path="System">*</Select>\
                    <Select Path="Security">*</Select>\
                    <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>\
                    <Select Path="Microsoft-Windows-PowerShell/Operational">*</Select>\
                    <Select Path="Microsoft-Windows-Windows Defender/Operational">*</Select>\
                </Query>\
            </QueryList>
    Exec if ($EventID == 5156) OR ($EventID == 5158) drop();
</Input>

<Output out>
    Module om_tcp
    Host    %OUTPUT_DESTINATION_ADDRESS%
    Port    %OUTPUT_DESTINATION_PORT%
    Exec    $EventTime = integer($EventTime) / 1000000;
    Exec    $Hostname = hostname_fqdn();
    Exec    $EventReceivedTime = integer($EventReceivedTime) / 1000000;
    Exec    $Message = to_json(); to_syslog_bsd();
</Output>

<Route 1>
Path eventlog, internal => out
</Route>

'@

$NxLogIISConfiguration = @'

############################################################################
####                             IIS-NXLOG                             #####
############################################################################

<Extension IIS_w3c>
   Module xm_csv
   Fields CHANGEME_NXLOG_FIELDS
   FieldTypes CHANGEME_NXLOG_FIELDTYPES
   Delimiter ' '
</Extension>

<Input IIS_IN>
   Module im_file
   CHANGEME_NXLOG_IIS_LOGGING_DIRECTORIES
   Recursive TRUE
   SavePos TRUE

   Exec if $raw_event =~ /^#/ drop(); \
   else \
   { \
     IIS_w3c->parse_csv(); \
     $EventTime = parsedate($date + " " + $time); \
     $SourceName = "IIS"; \
   }
</Input>

<Output IIS_OUT>
    Module om_tcp
    Host    %OUTPUT_DESTINATION_ADDRESS%
    Port    %OUTPUT_DESTINATION_PORT%
    Exec $EventTime = strftime($EventTime, '%Y-%m-%d %H:%M:%S');
    Exec $Hostname = hostname_fqdn();
    Exec $Message = to_json(); to_syslog_bsd();
</Output>

<Route IIS_Route>
   Path IIS_IN => IIS_OUT
</Route>

############################################################################
####                             IIS-NXLOG                             #####
############################################################################

'@

$NxLogApacheConfiguration = @'

#########################################################################
####                        APACHE-NXLOG                            #####
####   If Xampp is not used replace the path with the according one #####
#########################################################################

<Input APACHE_IN>
   Module  im_file
   File    "CHANGEME_APACHE_ACCESSLOG"
   Exec    $SourceName = "APACHE-NXLOG";
</Input>

<Output APACHE_OUT>
   Module om_tcp
   Host    %OUTPUT_DESTINATION_ADDRESS%
   Port    %OUTPUT_DESTINATION_PORT%
   Exec      to_syslog_bsd();
</Output>

<Route Apache>
   Path APACHE_IN => APACHE_OUT
</Route>

#########################################################################
####                        APACHE-NXLOG                            #####
#########################################################################

'@

$NxLogFirewallConfiguration = @'

############################################################################
####                          WINDOWS-FW-NXLOG                         #####
############################################################################

<Extension transform_alienvault_csv_windows_firewall>
   Module          xm_csv
   Fields          date, time, action, protocol, src-ip, dst-ip, src-port, dst-port, size, tcpflags, tcpsyn, tcpack, tcpwin, icmptype, icmpcode, info, path
   FieldTypes      string, string, string, string, string, string, string, string, string, string, string, string, string, string, string, string, string
   Delimiter       ' '
</Extension>

<Input FW_IN>
   Module      im_file
   File        "CHANGEME_WINDOWS_FIREWALL"
   SavePos     TRUE
   InputType   LineBased
      Exec if $raw_event =~ /^#/ drop();\
      else\
       {\
               transform_alienvault_csv_windows_firewall->parse_csv();\
               $EventTime = parsedate($date + " " + $time); \
               $Message = $raw_event; \
               $SourceName = "WINDOWS-FW";\
       }
</Input>

<Output FW_OUT>
   Module om_tcp
   Host    %OUTPUT_DESTINATION_ADDRESS%
   Port    %OUTPUT_DESTINATION_PORT%
   Exec $EventTime = strftime($EventTime, '%Y-%m-%d %H:%M:%S, %z');
   Exec $Message = to_json(); to_syslog_bsd();
</Output>

<Route route_windows_fw_nxlog>
   Path        FW_IN => FW_OUT
</Route>

############################################################################
####                          WINDOWS-FW-NXLOG                         #####
############################################################################

'@

$NxLogDHCPConfiguration = @'

############################################################################
####                             DHCP-NXLOG                            #####
####     Use "system32" if NxLog x64 is used on x64 systems            #####
####     Use "sysnative" if NxLog x86 is used on x64 systems           #####
############################################################################

<Extension transform_alienvault_dhcp_csv>
    Module          xm_csv
    Fields          $EventReceivedTime, $Message
    FieldTypes      string, string
    Delimiter       ;
</Extension>


<Input DHCP_IN>
    Module      im_file
    File        "C:\\Windows\\system32\\dhcp\\DhcpSrvLog-*.log"
    SavePos     TRUE
    InputType   LineBased
    Exec        if $raw_event =~ /^[0-3][0-9],/\
                {\
                      $Message = $raw_event;\
                      if $Message =~ s/^00/1000/;\
                      $raw_event = to_json();\
                      $SourceName = "DHCP-NXLOG";\
                }\
                else\
                      drop();
</Input>

<Output DHCP_OUT>
    Module om_tcp
    Host        %OUTPUT_DESTINATION_ADDRESS%
    Port        %OUTPUT_DESTINATION_PORT%
    Exec        $Hostname = hostname_fqdn();
    Exec        transform_alienvault_dhcp_csv->to_csv(); to_syslog_bsd();
</Output>

<Route DHCP>
    Path DHCP_IN => DHCP_OUT
</Route>

############################################################################
####                             DHCP-NXLOG                            #####
############################################################################

'@

$NxLogDNSConfiguration = @'

#######################################################################
####                          DNS-NXLOG                           #####
#######################################################################

<Input DNS_IN>
   Module    im_file
   File    "CHANGEME_DNS"
   SavePos  TRUE
   InputType LineBased
   Exec if ($raw_event =~ /^#/) OR ($raw_event == '') drop();\
       else\
           {\
           $Message = $raw_event;\
           $SourceName = "DNS";\
           $raw_event = to_json();\
           }
</Input>

<Output DNS_OUT>
   Module          om_tcp
   Host            %OUTPUT_DESTINATION_ADDRESS%
   Port            %OUTPUT_DESTINATION_PORT%
   Exec            if not defined $Message { drop(); }
   Exec            $Message = replace($Message, "a.m.", "AM");
   Exec            $Message = replace($Message, "p.m.", "PM");

   Exec            $Message = replace($Message, "\t", " "); $Message = replace($Message, "\n", " "); $Message = replace($Message, "\r", " ");

   Exec            if not defined $AccountName { $AccountName = "-"; }
   Exec            if not defined $AccountType { $AccountType = "-"; }
   Exec            if not defined $Domain { $Domain = "-"; }

   Exec	    	 $Hostname = hostname_fqdn();
   Exec            $raw_event = $Hostname + ' DNS-NXLOG: ' + $raw_event;
   Exec            $Message = to_json(); to_syslog_bsd();
</Output>

<Route route_dns_nxlog>
   Path        DNS_IN => DNS_OUT
</Route>

#######################################################################
####                          DNS-NXLOG                           #####
#######################################################################

'@

$NxLogNetlogonConfiguration = @'

#######################################################################################################
####                                      WINDOWS-NETLOGON-NXLOG                                  #####
#######################################################################################################

<Input WINDOWS_NETLOGON_IN>
    Module         im_file
    File           "C:\\Windows\\debug\\netlogon.log"
    SavePos        TRUE
    InputType      LineBased
    Exec if ($raw_event =~ /^#/) OR ($raw_event == '') drop();\
    else\
    {\
        $Message = $raw_event;\
        $SourceName = "WINDOWS-NETLOGON-NXLOG";\
        $raw_event = to_json();\
    }
</Input>

<Output WINDOWS_NETLOGON_OUT>
    Module         om_tcp
    Host           %OUTPUT_DESTINATION_ADDRESS%
    Port           %OUTPUT_DESTINATION_PORT%

    Exec           $Hostname = hostname_fqdn();
    Exec           $raw_event = $Hostname + ' WINDOWS-NETLOGON-NXLOG: ' + $raw_event;
    Exec           $Message = to_json(); to_syslog_bsd();
</Output>

<Route route_netlogon_nxlog>
    Path        WINDOWS_NETLOGON_IN => WINDOWS_NETLOGON_OUT
</Route>

#######################################################################################################
####                                      WINDOWS-NETLOGON-NXLOG                                  #####
#######################################################################################################

'@

$NxLogMSSQLConfiguration = @'

######################################################################################
####                                 MSSQL-NXLOG                                 #####
####  The audit mssql logs must be added to Application when enabling auditing.  #####
######################################################################################

<Input MSSQL_IN>
  Module          im_msvistalog
  SavePos         FALSE
  ReadFromLast    TRUE

  Query          <QueryList>                                         \
                     <Query Id="0">                                  \
                         <Select Path="Application">*[System[(EventID='33205')]]</Select>\
                     </Query>                                    \
                 </QueryList>
  Exec			$Message = $raw_event;
  Exec           if $raw_event =~ /^#/ drop();\
                 else\
                 {\
                     $SourceName = "MSSQL-NXLOG";\
                 }

  Exec			 if $raw_event =~ /action_id:(\S+)/ $Action_ID = $1;
  Exec			 if $raw_event =~ /database_name:(\S+)/ $DataBase = $1;
  Exec			 if $raw_event =~ /server_instance_name:(\S+)/ $SV_Instace = $1;
  Exec			 if $raw_event =~ /session_server_principal_name:(\S+)/ $User = $1;
  Exec			 if $raw_event =~ /AUDIT_SUCCESS/\
  {\
    $Result = 'Success';\
  }\
  else\
    $Result = 'Failure';
  Exec            $Message = replace($Message, "\t", " "); $Message = replace($Message, "\n", " "); $Message = replace($Message, "\r", " ");
</Input>

<Output MSSQL_OUT>
  Module        om_ssl
  CAFile        %CERTDIR%\USM-Anywhere-Syslog-CA.cer
  Host          %OUTPUT_DESTINATION_ADDRESS%
  Port          %OUTPUT_DESTINATION_PORT%
  Exec 			$Message = to_json(); to_syslog_bsd();
</Output>

<Route mssql>
  Path            MSSQL_IN => MSSQL_OUT
</Route>

######################################################################################
####                                 MSSQL-NXLOG                                 #####
######################################################################################

'@

$NxLogNPSConfiguration = @'

############################################################################
####                         NPS-NXLOG                                 #####
####     Use "system32" if NxLog x64 is used on x64 systems            #####
####     Use "sysnative" if NxLog x86 is used on x64 systems           #####
############################################################################

<Extension xmlparser>
  Module xm_xml
</Extension>

<Input NPS_IN>
  Module im_file
  File "C:\\Windows\\system32\\LogFiles\\IN*.log"
  SavePos TRUE
  InputType LineBased
  Exec if ($raw_event =~ /^#/) OR ($raw_event == '') OR ($raw_event !~ /^<Event>/) drop();\
  else\
  {\
    parse_xml();\
    $Message = $raw_event;\
    $SourceName = "NPS-NXLOG";\
    $raw_event = to_json();\
  }
</Input>

<Output NPS_OUT>
  Module      om_tcp
  Host        %OUTPUT_DESTINATION_ADDRESS%
  Port        %OUTPUT_DESTINATION_PORT%
  Exec $Hostname = hostname_fqdn();
  Exec $Message = replace($Message, '"', "");
  Exec $Message = to_json(); to_syslog_bsd();
</Output>

<Route NPS>
  Path NPS_IN => NPS_OUT
</Route>

############################################################################
####                         NPS-NXLOG                                 #####
############################################################################

'@

function Get-TeamsTextBlock($ErrorMessage)
{
    return [Ordered]@{
        "type"    = "TextBlock"
        "text"    = "$ErrorMessage"
        "wrap"    = $true
    }
}

function Get-TeamsSuccessSheet()
{
    return [Ordered]@{
        "type" = "FactSet"
        "facts" = @(
            @{
                "title" = "Sysmon64"
                "value" = $SysmonStatus
            }
            @{
                "title" = "NxLog"
                "value" = $NxLogStatus
            }
            @{
                "title" = "IIS"
                "value" = $IISStatus
            }
            @{
                "title" = "Apache"
                "value" = $ApacheStatus
            }
            @{
                "title" = "DNS"
                "value" = $DNSStatus
            }
            @{
                "title" = "DHCP"
                "value" = $DHCPStatus
            }
            @{
                "title" = "NPS"
                "value" = $NPSStatus
            }
            @{
                "title" = "MS SQL Server"
                "value" = $MSSQLServerStatus
            }
            @{
                "title" = "Netlogon Debug"
                "value" = $NetlogonStatus
            }
        )
    }
}

function Get-TeamsJsonObject()
{
    return [Ordered]@{
        "type"       = "message"
        "attachments" = @(
            @{
                "contentType" = 'application/vnd.microsoft.card.adaptive'
                "content"     = [Ordered]@{
                    '$schema' = "<http://adaptivecards.io/schemas/adaptive-card.json>"
                    "type"    = "AdaptiveCard"
                    "version" = "1.4"
                    "body"    = [System.Collections.ArrayList]@(
                        [Ordered]@{
                            "type"    = "TextBlock"
                            "text"    = $(Get-EnvironmentInformation)
                            "spacing" = "None"
                            "wrap"    = $true
                        }
                        [Ordered]@{
                            "type"    = "ColumnSet"
                            "columns" = @(
                                @{
                                    "type"  = "Column"
                                    "width" = "auto"
                                    "items" = @(
                                        @{
                                            "type"  = "Image"
                                            "style" = "Person"
                                            "url"   = $IconUrl
                                            "size"  = "Small"
                                        }
                                    )
                                }
                                @{
                                    "type"  = "Column"
                                    "width" = "stretch"
                                    "items" = @(
                                        @{
                                            "type"   = "TextBlock"
                                            "weight" = "Bolder"
                                            "text"   = "$LocalMachineDNSName ($(Get-AllIPAddresses))"
                                            "wrap"   = $true
                                        }
                                        @{
                                            "type"     = "TextBlock"
                                            "spacing"  = "None"
                                            "text"     = "Executed: {{DATE($(Get-ExecutionDate))}} @ {{TIME($(Get-ExecutionDate))}}"
                                            "isSubtle" = $true
                                            "wrap"     = $true
                                        }
                                    )
                                }
                            )
                        }
                    )
                    "actions" = [System.Collections.ArrayList]@()
                }
            }
        )
    }
}

function Send-FailureNotification($Title, $ErrorMessage = '')
{
    $NotifyObject = Get-TeamsJsonObject
    $NotifyObject.attachments[0].content.body.Add($(Get-TeamsTextBlock $Title)) | Out-Null
    if (-not [string]::IsNullOrEmpty($ErrorMessage)) {
        $NotifyObject.attachments[0].content.body.Add($(Get-TeamsTextBlock $ErrorMessage)) | Out-Null
    }

    $JsonBody = $NotifyObject | ConvertTo-JSON -Depth 20

    try {
        Write-Host "`n[-] Sending error notification to MS Teams..."
        Invoke-RestMethod -Method POST -ContentType 'Application/Json' -Body $JsonBody -Uri $TeamsWebhookFailure | Out-Null
    }
    catch {
        Write-Host "`n[x] There was an error when attempting to send the webhook: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-USMIPAddress()
{
    # Check if override is present, if it is, use it
    if (Test-RegistryValue -Path $RegistryRootKey -Name $RegistrySensorOverride) {
        return (Get-RegistryValue -Path $RegistryRootKey -Name $RegistrySensorOverride)
    }

    try {
        # Try to get the matching USM IP for the subscription, if this fails, use the default IP
        $ip = $SensorIP
        if ([string]::IsNullOrEmpty($ip)) {
            throw [System.IO.FileNotFoundException] "IP Address cannot be blank"
        }
        return $ip
    }
    catch [System.Exception] {
        Write-Host "`n[x] Sensor could not be discovered automatically, using default sensor..." -ForegroundColor Red
        Send-FailureNotification "Function: Get-USMIPAddress failed to determine an IP address for the sensor, using default IP instead" $_.Exception.Message
    }

    return $UsmDefaultIp
}

function Send-SuccessNotification()
{
    $SysmonStatus = Get-ServiceStatus $SysmonServiceName
    $NxLogStatus = Get-ServiceStatus $NxLogServiceName

    $SensorStatus = "Sensor: $UsmIp "
    if ($NxLogSyslogTls) {
        $SensorStatus += "with TLS"
    } else {
        $SensorStatus += "**without TLS**"
    }

    $NotifyObject = Get-TeamsJsonObject
    $NotifyObject.attachments[0].content.body.Add($(Get-TeamsTextBlock $SensorStatus)) | Out-Null
    $NotifyObject.attachments[0].content.body.Add($(Get-TeamsSuccessSheet)) | Out-Null

    $NotifyObject.attachments[0].content.actions.Add(
        [Ordered]@{
            "type"    = "Action.OpenUrl"
            "title"    = "See Events by DNS Name"
            "url"    = $AlienVaultUrlDNS
        }
    ) | Out-Null

    Get-TeamsUSMButtonsForAllIPs | ForEach-Object {
        $NotifyObject.attachments[0].content.actions.Add($_) | Out-Null
    }

    $JsonBody = $NotifyObject | ConvertTo-JSON -Depth 20

    try {
        Write-Host "`n[-] Sending notification to MS Teams..."
        Invoke-RestMethod -Method POST -ContentType 'Application/Json' -Body $JsonBody -Uri $TeamsWebhookSuccess | Out-Null
    }
    catch {
        Write-Host "`n[x] There was an error when attempting to send the webhook: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-UpdateScriptCheck() {
    # This function will check the existing update script and see if it matches the hash of the new one, and if not, it will update the existing script and re-create the Scheduled Task.
    # WARNING: Ensure that this script is hosted on a Windows platform with CRLF line endings otherwise the hash will not match the existing file and it will be overwritten.
    $updateFile = Join-Path -Path $MDRDirectory -ChildPath $UpdateScriptLocation
    if (Test-Path -Path $updateFile -PathType Leaf) {
        $updateHash = (Get-FileHash -Path $updateFile -Algorithm SHA256).Hash

        if ("F69C2944ABF528B02E56D948092E04F796DE22DA44B50F4C1A81932D4748B9FE" -ne $updateHash) {
            Write-Host "`nOld update file found, updating..."
            Add-UpdateScript
        }
    }
}

function Add-UpdateScript() {
    Write-Host "`n[-] Setting up scheduled update task..."
    $updateFile = Join-Path -Path $MDRDirectory -ChildPath $UpdateScriptLocation
    if (Test-Path -Path $updateFile -PathType Leaf) {
        Remove-Files $updateFile
    }
    [IO.File]::WriteAllBytes($updateFile, [Convert]::FromBase64String($UpdateScriptContents))
    Write-Host "[+] Update file created" -ForegroundColor Green

    if (Get-ScheduledTask | Where-Object {$_.TaskName -like $UpdateScriptTaskName }) {
        Unregister-ScheduledTask -TaskName $UpdateScriptTaskName -Confirm:$false
    }

    # Task doesn't exist, create it
    $taskAction = New-ScheduledTaskAction `
        -Execute 'powershell.exe' `
        -Argument "-File $updateFile"

    $hours = (Get-Random -Minimum 1 -Maximum 5)
    $minutes = ("{0:D2}" -f (Get-Random -Minimum 0 -Maximum 60))
    $taskTrigger = New-ScheduledTaskTrigger -Daily -At "${hours}:${minutes}AM"

    $description = "MDR - An automated update job to ensure the NxLog configuration file remains current and valid - Job owned by Infosec - Created by Rob Emmerson on 13/07/2022."
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1)

    Register-ScheduledTask `
        -TaskName $UpdateScriptTaskName `
        -Action $taskAction `
        -Trigger $taskTrigger `
        -Description $description `
        -Principal $principal `
        -Settings $settings `
        | Out-Null

    Write-Host "[+] Scheduled task created" -ForegroundColor Green
}

function Initialize-SubscriptionDetection()
{
    Set-Variable -Name "IsAzure" -Value (Get-IsInAzure) -Scope Script
    if (-not $IsAzure) {
        Set-Variable -Name "IsAws" -Value (Get-IsInAWS) -Scope Script
    }

    if ($IsAzure) {
        Set-Variable -Name "SubscriptionId" -Value (Get-AzureSubscriptionId) -Scope Script
        Write-Host "`n[+] Azure VM Detected - Subscription ID: $SubscriptionId" -ForegroundColor Green
    }
    elseif ($IsAws) {
        Set-Variable -Name "SubscriptionId" -Value (Get-AwsSubscriptionId) -Scope Script
        Write-Host "`n[+] AWS VM Detected - Subscription ID: $SubscriptionId" -ForegroundColor Green
    }
    else {
        Set-Variable -Name "SubscriptionId" -Value '1ddbc74f-5f85-4075-bfd6-05f6a4f90bbf' -Scope Script # Service Delivery UK - default sensor
        Write-Host "`n[+] Unknown Location Detected, using default sensor" -ForegroundColor Green
    }


    $SubName = $SubscriptionId
    
    Set-Variable -Name "SubName" -Value ($SubName) -Scope Script
}

# This has been created for future use, the update script will incorporate this function and we should transition away from trying to do software updates inside the NxLog update function
function Invoke-UpdateChecks() {
    # TODO: Implement checks for Syslog, NxLog & the scheduled task here...
}

function Install-MDR($SensorIP = '', $ApacheLogFile = '', [switch]$Isolated)
{
    # Setup logging so we have a record of the installation
    $LogFilenameDate = (Get-Date).toString("yyyy-MM-dd")
    $LogFilename = "install-$LogFileNameDate.log"
    $InstallFile = Join-Path -Path $MDRDirectory -ChildPath "installed"
    
    try {
        # Create the location to store logs
        New-Item $MDRDirectory -ItemType "directory" -Force | Out-Null
        $logFile = Join-Path -Path $MDRDirectory -ChildPath $LogFilename
    }
    catch {
        $logFile = Join-Path -Path $env:TEMP -ChildPath $LogFilename
        Write-Host "Unable to create standard logging file, script will log to a temporary file instead: $logFile" -ForegroundColor Red
    }

    Start-Transcript -Path $logFile -Append
    Write-Host "[-] Start Time: $((Get-Date).toString("yyyy/MM/dd HH:mm:ss"))" -ForegroundColor Yellow

    # If Apache is set, store it in the registry for later config rebuilds
    if (-not [string]::IsNullOrEmpty($ApacheLogFile)) {
        Add-RegistryValue -Path $RegistryRootKey -Name $RegistryApacheLocation -Value $ApacheLogFile.Replace("\", "\\")
    } else {
        Remove-ItemProperty -Path $RegistryRootKey -Name $RegistryApacheLocation -ErrorAction SilentlyContinue
    }

    Initialize-SubscriptionDetection

    # Check if we're in the 'Service Delivery' Azure subscription and if so, make sure we're using the correct sensor
    if ($SubscriptionId -eq '1ddbc74f-5f85-4075-bfd6-05f6a4f90bbf') {
        $ComputerName = $env:COMPUTERNAME.ToUpper()

        if ($ComputerName -like 'AM*' -or $ComputerName -like 'AP*') {
            $SensorIP = 'avs-az-service_delivery-02.global.root'
            Set-Variable -Name "SensorIP" -Value 'avs-az-service_delivery-02.global.root' -Scope Script
        }
    }

    # Store any sensor IP overrides for later config rebuilds
    if (-not [string]::IsNullOrEmpty($SensorIP)) {
        Add-RegistryValue -Path $RegistryRootKey -Name $RegistrySensorOverride -Value $SensorIP
    } else {
        Remove-ItemProperty -Path $RegistryRootKey -Name $RegistrySensorOverride -ErrorAction SilentlyContinue
    }

    Install-SysmonMonitor
    Install-NxLog

    Write-Host "`n[-] Checking that services are running..."
    CheckRunningServices $NxLogServiceName
    CheckRunningServices $SysmonServiceName

    # Setup Update Job if the machine is not isolated
    if (-not $Isolated) {
        Add-UpdateScript
    }

    if (-not (Test-Path -Path $InstallFile)) {
        New-Item -Path $InstallFile -ItemType File | Out-Null # Created install file so SSM job doesn't re-run the script
    }

    Send-SuccessNotification

    Write-Host "`nEnd Time: $((Get-Date).toString("yyyy/MM/dd HH:mm:ss"))" -ForegroundColor Yellow
    Stop-Transcript

    Remove-Item -Path Function:\Clear-Variables -ErrorAction SilentlyContinue
}
