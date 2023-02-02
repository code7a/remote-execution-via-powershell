#Remote Execution via PowerShell to Windows Hosts
```powershell
#Remote Execution via PowerShell to Windows Hosts
#Requires -RunAsAdministrator

#Copyright 2023
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

## Variables ##

#Windows host list file, new line delimited list of IPs or hostnames
$WindowsHostList=Get-Content .\WindowsHostList.txt

#Remote execution command, enter command or commands between @" and "@
$WindowsRemoteExecutionCommand=@"
hostname
"@

## Code ##

#If not Administrator, exit
$Role=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
If(-not $Role){Write-Host "ERROR: Run as Administrator" -ForegroundColor Red; Exit}

#Set credentials
$WindowsAdministratorCredentials=Get-Credential -Message "Enter Windows Administrator credentials."

#Configure WinRM, add servers as trusted
foreach ($WindowsHost in $WindowsHostList) {
    Set-Item WSMan:\localhost\Client\TrustedHosts -Concatenate -Value "$WindowsHost" -Force
}

#Remote execution
foreach ($WindowsHost in $WindowsHostList) {
    Invoke-Command -AsJob -ComputerName $WindowsHost -ScriptBlock {$args|Invoke-Expression} -Credential $WindowsAdministratorCredentials -ArgumentList $WindowsRemoteExecutionCommand
}
```

#Remote Execution via PowerShell to Linux Hosts
```powershell
#Remote Execution via PowerShell to Linux Hosts
#Requires -RunAsAdministrator

#Copyright 2023
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

## Variables ##

#Linux host list file, new line delimited list of IPs or hostnames
$LinuxHostList=Get-Content .\LinuxHostList.txt

#Remote execution command, enter command or commands between @" and "@
$LinuxRemoteExecutionCommand=@"
hostname
"@

## Code ##

#If not Administrator, exit
$Role=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
If(-not $Role){Write-Host "ERROR: Run as Administrator" -ForegroundColor Red;Exit}

#Install Windows Powershell module for SSH
#https://github.com/darkoperator/Posh-SSH
Install-Module -Name Posh-SSH -Force

#Set credentials
$LinuxCredentials=Get-Credential -Message "Enter Linux credentials."

#Remote execution
foreach ($LinuxHost in $LinuxHostList) {
    $SSHSession=New-SSHSession -ComputerName $LinuxHost -Credential $LinuxCredentials -AcceptKey
    Invoke-SSHCommand -SessionId $SSHSession.SessionId -Command $LinuxRemoteExecutionCommand
}
```