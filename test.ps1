Invoke-WebRequest "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile sysmonlatest.xml -UseBasicParsing
Invoke-WebRequest "https://github.com/oloruntolaallbert/powershell/blob/main/sysmon.zip" -OutFile "sysmon.zip" -UseBasicParsing
Expand-Archive "sysmon.zip" -Force

if ([Environment]::Is64BitOperatingSystem) {
Copy-Item ".\sysmon64.exe" "C:\windows\system32\sysmon64.exe"
Start-Process "C:\Windows\system32\Sysmon64.exe" -ArgumentList "-accepteula -i sysmonlatest.xml"
Start-Process "C:\Windows\system32\Sysmon64.exe" -ArgumentList "-accepteula -c sysmonlatest.xml"
}
else {
Copy-Item ".\sysmon.exe" "C:\windows\system32\sysmon.exe"
Start-Process "C:\Windows\system32\Sysmon.exe" -ArgumentList "-accepteula -i sysmonlatest.xml"
Start-Process "C:\Windows\system32\Sysmon.exe" -ArgumentList "-accepteula -c sysmonlatest.xml"
}
