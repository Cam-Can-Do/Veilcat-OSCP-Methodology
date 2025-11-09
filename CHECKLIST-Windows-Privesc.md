# Windows Privilege Escalation Checklist

**DO NOT SKIP STEPS.** Check every box in order. This prevents missing obvious vectors.

## Initial Enumeration (Always Run First)

- [ ] Run WinPEAS: `.\winPEASx64.exe | Tee-Object winpeas_output.txt`
- [ ] Check current user and privileges: `whoami /all`
- [ ] Check local users: `net user` and `net localgroup administrators`
- [ ] Check system info: `systeminfo`
- [ ] Check network config: `ipconfig /all` (multiple NICs? Note for pivoting)
- [ ] Check listening ports: `netstat -ano` (internal services to enumerate?)

## Immediate Win Checks (Check These FIRST)

- [ ] **SeImpersonatePrivilege enabled?** `whoami /priv` → If YES, use SweetPotato immediately
- [ ] **SeAssignPrimaryTokenPrivilege enabled?** → If YES, use SweetPotato immediately
- [ ] **In Administrators group?** `whoami /groups` → If YES, you may already have admin (UAC bypass?)
- [ ] AlwaysInstallElevated set? `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`

## Credential Hunting (DO NOT SKIP - Even If You Have Admin)

**Your biggest weakness: Skipping this after initial access. ALWAYS CHECK:**

- [ ] PowerShell history for ALL users: `Get-ChildItem -Path C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -Recurse -ErrorAction SilentlyContinue`
- [ ] Read each history file: `type <path>` (look for passwords, admin commands)
- [ ] Check for interesting files in user directories: `Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.kdbx,*.exe -Recurse -ErrorAction SilentlyContinue`
- [ ] Download and `strings` any unusual .exe files found (may contain hardcoded creds)
- [ ] Registry autologon creds: `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"`
- [ ] Saved credentials: `cmdkey /list`
- [ ] Search for passwords in files: `findstr /si "password" C:\Users\*.txt C:\Users\*.xml C:\Users\*.ini 2>nul`

## Web Application Enumeration (If Web Server Present)

**CRITICAL: Don't assume you found everything. Port 80/8000/8080 running?**

- [ ] Check for web directories: Review autorecon feroxbuster results thoroughly
- [ ] Look for databases: Check web app directory for .db, .sqlite, .sql files
- [ ] Check web configs: Find config files (web.config, config.php, settings.py) with DB creds
- [ ] Test DB access: If you find DB creds, connect and dump (MySQL, MSSQL, SQLite)
- [ ] Check for exposed directories: /admin, /backup, /db, /config, /setup (manual curl if needed)

## Database Access (If Database Service Running)

- [ ] Check netstat output: MySQL (3306/3307)? MSSQL (1433/1435)? SQLite files?
- [ ] Test default creds: `mysql -u root -p` (try empty password), MSSQL as current user
- [ ] If DB access works, enumerate all databases and tables for credentials
- [ ] Check for password hashes to crack offline

## Service Exploitation

- [ ] Check for unquoted service paths: `Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notlike '*"*' -and $_.PathName -like '* *'}`
- [ ] Check service permissions: Look in WinPEAS output for modifiable services
- [ ] Check writable service binaries: Can you replace any service .exe?
- [ ] Check scheduled tasks: `schtasks /query /fo LIST /v` (writable task binaries?)

## After Getting SYSTEM (DO NOT SKIP THIS)

**EVEN WITH SYSTEM, enumerate for lateral movement credentials:**

- [ ] Run Mimikatz: `.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > mimikatz.txt`
- [ ] Review Mimikatz output: Extract all NTLM hashes and plaintext passwords
- [ ] Test credentials across domain/network: `netexec smb <targets> -u <users> -H <hashes>`
- [ ] Re-check PowerShell histories: `type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- [ ] Check for additional unusual files/programs missed earlier
- [ ] Review network interfaces: `ipconfig /all` → Pivoting needed?

## Common Pitfalls

**STOP and re-check if stuck for 15+ minutes:**
- Did you check `whoami /priv` for SeImpersonate? (This is the #1 quick win)
- Did you read PowerShell history for ALL users thoroughly?
- Did you enumerate web directories if port 80/8000/8080 is open?
- Did you check for databases and try to access them?
- Did you search for .exe files and use `strings` on them?
- Did you actually READ the WinPEAS output instead of skimming?

## DO NOT ASSUME Patterns

**Lessons from your Challenge Labs:**
- ❌ "I have admin, don't need to enumerate more" → WRONG. Check history, mimikatz, files
- ❌ "I ran autorecon, that's enough" → WRONG. Manually review feroxbuster output line-by-line
- ❌ "No obvious web vulns, skip it" → WRONG. Look for exposed /DB, databases, config files
- ❌ "I found one credential, done searching" → WRONG. Keep hunting for more

## Reference

For detailed commands, see [[Windows Privilege Escalation]]
