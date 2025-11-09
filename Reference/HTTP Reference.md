# HTTP/HTTPS Reference

Quick reference for less common HTTP enumeration scenarios. For core commands, see [[80, 443 HTTP]].

## Directory Enumeration Strategy

**Wordlist selection:**
- Fast initial scan: `common.txt`
- Comprehensive: `raft-large-directories.txt`
- Targeted by tech stack: ASP.NET (.aspx, .asmx), PHP (.php), Java (.jsp, .do)

## Manual Source Code Review

Always check page source for:
- Hidden form fields with default values
- JavaScript files containing API endpoints
- Comments with credentials or file paths
- AJAX endpoints in JavaScript
- Hardcoded API keys or tokens

## Local File Inclusion (LFI) Deep Dive

**Common vulnerable parameters:** `?file=`, `?page=`, `?include=`, `?path=`, `?doc=`, `?template=`

**Linux targets:**
- `/etc/passwd`
- `/etc/shadow` (if readable)
- `/var/log/apache2/access.log`
- `/var/log/auth.log`
- `/proc/self/environ`

**Windows targets:**
- `C:\windows\system32\drivers\etc\hosts`
- `C:\windows\win.ini`
- `C:\inetpub\wwwroot\web.config`

**PHP wrappers:**
- `php://filter/convert.base64-encode/resource=config.php`
- `php://input` (for code execution via POST data)
- `data://text/plain;base64,<encoded PHP>`

## Log Poisoning for RCE

**Common log locations (Linux):**
- `/var/log/apache2/access.log`, `/var/log/apache2/error.log`
- `/var/log/nginx/access.log`
- `/var/log/auth.log` (SSH logs)
- `/var/log/mail.log`, `/var/log/vsftpd.log`

**Common log locations (Windows):**
- `C:\xampp\apache\logs\access.log`
- `C:\wamp\logs\access.log`
- `C:\inetpub\logs\LogFiles\W3SVC1\`

**Steps:**
1. Inject PHP payload into log (via User-Agent, SSH username, etc.)
2. Use LFI to include the poisoned log file
3. Pass commands via GET parameter

## File Upload Bypass Techniques

- Double extensions: `shell.php.jpg`
- Null byte injection: `shell.php%00.jpg`
- Case variation: `shell.PhP`
- Content-Type manipulation
- Upload `.htaccess` to allow PHP execution
- Upload web shells disguised as images

## CMS Enumeration Details

**WordPress:**
- Default admin: `/wp-admin/`
- XML-RPC: `/xmlrpc.php`
- User enumeration: `/?author=1`

**Joomla:**
- Default admin: `/administrator/`
- Configuration: `/configuration.php`
- CHANGELOG.txt reveals version

**Drupal:**
- Default admin: `/user/login`
- CHANGELOG.txt reveals version

## Command Injection Test Payloads

```
; whoami
| whoami
& whoami
&& whoami
`whoami`
$(whoami)
```

## Resources

- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security: https://portswigger.net/web-security
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks Web Pentesting: https://book.hacktricks.xyz/pentesting-web/
