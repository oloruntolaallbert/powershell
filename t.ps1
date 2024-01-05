#param(
 #   [Parameter(Mandatory = $true, HelpMessage = "Sensor IP is required.")]
  #  [string]$SensorIP
#)

# Set ThreadOptions to ReuseThread if possible to help mitigate memory leaks
if (($ver = $host | Select-Object -ExpandProperty Version).Major -gt 1) {
    $Host.Runspace.ThreadOptions = "ReuseThread"
}

# Ensure TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try {
    # Check if the user running the script is an administrator and elevate if not
    $IsAdmin = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($IsAdmin)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "You must run this script as an Administrator."
    }

    # Define variables for Sysmon installation
    $SysmonUrl = "https://github.com/oloruntolaallbert/powershell/blob/main/Sysmon64.exe" # download URL for Sysmon
    $SysmonDest = "$env:TEMP\Sysmon64.exe"
    $SysmonConfigUrl = "https://raw.githubusercontent.com/kinnairdt/Scripts/main/mdr-supporting-files-main/sysmon_config_schema4_0.xml" # URL to Sysmon configuration XML
    $SysmonConfigDest = "$env:TEMP\sysmonconfig.xml"

    # Download Sysmon executable and configuration file
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $SysmonDest -UseBasicParsing
    Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $SysmonConfigDest -UseBasicParsing

    # Install Sysmon with the provided configuration
    Start-Process -FilePath $SysmonDest -ArgumentList "-accepteula -i $SysmonConfigDest" -Wait

    # Define variables for NxLog installation
    $NxLogUrl = "https://github.com/kinnairdt/Scripts/blob/main/mdr-supporting-files-main/nxlog.msi" #URL for NxLog
    $NxLogDest = "$env:TEMP\nxlog.msi"
    $NxLogConfigUrl = "https://example.com/nxlog.conf" # Replace with the actual URL to your NxLog configuration file
    $NxLogConfigDest = "$env:ProgramFiles\nxlog\conf\nxlog.conf"

    # Download and install NxLog silently without a UI
    Invoke-WebRequest -Uri $NxLogUrl -OutFile $NxLogDest -UseBasicParsing
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $NxLogDest /quiet" -Wait

    # Wait a few seconds to ensure NxLog service installation is complete
    Start-Sleep -Seconds 10

    # Apply the NxLog configuration
    Invoke-WebRequest -Uri $NxLogConfigUrl -OutFile $NxLogConfigDest -UseBasicParsing

    # Start the NxLog service
    Start-Service -Name "nxlog"

    # Confirm completion
    Write-Host "Installation and configuration of Sysmon and NxLog are complete."

    # Define the sensors array
    $Sensors = @(
        @{
            "IPAddress" = $SensorIP
        }
    )

    # Additional logic related to sensors may be added here...

    # If the whole script succeeds, you may want to notify via webhook
    # Send notification to Teams webhook for success (code to send a notification goes here)

} catch {
    # Handle exceptions
    Write-Error $_.Exception.Message

    # If running as an administrator is required, attempt to restart the script with elevated privileges
    if ($_.Exception.Message -like "*Administrator*") {
        $newProcess = [System.Diagnostics.ProcessStartInfo]::new()
        $newProcess.FileName = "PowerShell"
        $newProcess.Arguments = $MyInvocation.MyCommand.Definition
        $newProcess.Verb = "runas"
        
        # Start the new process
        [System.Diagnostics.Process]::Start($newProcess)
        exit
    }
}
    # Send notification to Teams webhook for failure (code to send a notification goes here)
