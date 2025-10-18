# Evidence Collection & Reporting

## Display Windows hostname

```cmd
hostname
```

## Display current Windows user

```cmd
whoami
```

## Display Windows user privileges

```cmd
whoami /priv
```

## Display Windows system information summary

```cmd
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version"
```

## Display full Windows system information

```cmd
systeminfo
```

## Display Windows user flag

```cmd
type C:\Users\user\Desktop\user.txt
```

## Display Windows admin flag

```cmd
type C:\Users\Administrator\Desktop\proof.txt
```

## Search for all user flags on Windows

```cmd
dir C:\Users\*\Desktop\*.txt /s
```

## Display Windows XP admin flag alternate location

```cmd
type "C:\Documents and Settings\Administrator\Desktop\proof.txt"
```

## Display Windows network configuration

```cmd
ipconfig /all
```

## Display Windows routing table

```cmd
route print
```

## Display Linux hostname

```bash
hostname
```

## Display current Linux user

```bash
whoami
```

## Display Linux user ID and groups

```bash
id
```

## Display Linux kernel version

```bash
uname -a
```

## Display Linux OS release information

```bash
cat /etc/os-release
```

## Display Linux user flag

```bash
cat /home/user/user.txt
```

## Display Linux root flag

```bash
cat /root/proof.txt
```

## Search for user flag on Linux

```bash
find / -name "user.txt" 2>/dev/null
```

## Search for root flag on Linux

```bash
find / -name "proof.txt" 2>/dev/null
```

## Display Linux network interfaces

```bash
ip addr show
```

## Display Linux routing table

```bash
ip route show
```

## Display network interfaces using ifconfig

```bash
ifconfig -a
```

## Create timestamped screenshot

```bash
scrot "$(date +%Y%m%d_%H%M%S)_screenshot.png"
```

## Display file details with ls

```bash
ls -la file.txt
```

## Display file details with dir

```cmd
dir file.txt
```

## Calculate MD5 hash on Linux

```bash
md5sum file.txt
```

## Calculate SHA256 hash on Linux

```bash
sha256sum file.txt
```

## Calculate MD5 hash on Windows

```cmd
certutil -hashfile file.txt MD5
```

## Calculate SHA256 hash on Windows

```cmd
certutil -hashfile file.txt SHA256
```

## Display current date and time on Linux

```bash
date
```

## Display current date on Windows

```cmd
date /t
```

## Display current time on Windows

```cmd
time /t
```

## List running processes on Windows

```cmd
tasklist
```

## List running processes on Linux

```bash
ps aux
```

## Display listening ports on Windows

```cmd
netstat -ano
```

## Display listening ports on Linux

```bash
netstat -tulpn
```

## Display listening ports using ss

```bash
ss -tulpn
```

## Check current working directory on Linux

```bash
pwd
```

## Check current working directory on Windows

```cmd
cd
```

## Display environment variables on Linux

```bash
env
```

## Display environment variables on Windows

```cmd
set
```

## Display user accounts on Windows

```cmd
net user
```

## Display user details on Windows

```cmd
net user username
```

## Display local administrators on Windows

```cmd
net localgroup administrators
```

## Display user accounts on Linux

```bash
cat /etc/passwd
```

## Display groups on Linux

```bash
cat /etc/group
```

## Display sudo privileges on Linux

```bash
sudo -l
```

## Check command history on Linux

```bash
cat ~/.bash_history
```

## Check PowerShell history on Windows

```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath
```

## Display scheduled tasks on Windows

```cmd
schtasks /query /fo LIST /v
```

## Display cron jobs on Linux

```bash
crontab -l
cat /etc/crontab
```

## Display Windows services

```cmd
sc query
```

## Display Linux services

```bash
systemctl list-units --type=service
```

## Save command output to file on Linux

```bash
whoami > output.txt
id >> output.txt
hostname >> output.txt
```

## Save command output to file on Windows

```cmd
whoami > output.txt
hostname >> output.txt
systeminfo >> output.txt
```

## Create evidence collection script on Linux

```bash
echo "=== SYSTEM INFORMATION ===" > evidence.txt
hostname >> evidence.txt
date >> evidence.txt
whoami >> evidence.txt
id >> evidence.txt
uname -a >> evidence.txt
cat /etc/os-release >> evidence.txt
```

## Display proof screenshot naming format

```
$IP_01_nmap_scan.png
$IP_02_web_enum.png
$IP_03_exploit.png
$IP_04_user_flag.png
$IP_05_privesc.png
$IP_06_root_flag.png
```

## Verify flag content is displayed correctly

```bash
cat /root/proof.txt
echo "Flag captured at: $(date)"
```

## Document exploitation command in notes

```bash
echo "Exploit: python3 exploit.py $IP" | tee -a notes.txt
```

## Capture full terminal output to log

```bash
script -a terminal_session.log
```

## Stop script logging session

```bash
exit
```

---

## Evidence Collection Philosophy

Documentation proves you successfully compromised each target during the OSCP exam. Without proper evidence, even successful exploitation cannot be validated. Screenshots and detailed notes are your proof of work.

## Mandatory Evidence Requirements

### For Each Compromised Machine

You must capture proof for both user-level and administrator/root-level access. Each proof requires specific screenshots showing command execution and flag content.

### User Flag Evidence
Screenshot must show the full path to user.txt, the cat/type command, complete flag content, username context with whoami, and hostname verification. This proves you achieved user-level access on the correct machine.

### Administrator/Root Flag Evidence
Screenshot must show the full path to proof.txt, the cat/type command, complete flag content, privileged user context, and hostname verification. This proves you achieved full system compromise.

### System Information Evidence
Document hostname, IP address, operating system version, current user and privileges, and timestamp of access. This provides context for the compromise.

## Screenshot Quality Standards

All screenshots must be high resolution with readable text, show the full terminal window, display both command and complete output, avoid cropping important information, and include clear timestamps when relevant. Poor quality screenshots may result in points being deducted.

## File Naming Conventions

Use descriptive names that include machine identifier, step number, and brief description. Examples: 10.10.10.5_01_nmap_initial.png, 10.10.10.5_04_user_flag_capture.png, 10.10.10.5_06_root_flag_capture.png. Consistent naming makes evidence organization much easier during report writing.

## Evidence Organization

Create a directory structure with folders for each machine containing subfolders for screenshots, scan results, exploits used, and flag captures. Maintain a master directory for the final report and compiled evidence. Good organization saves hours during report writing.

## Common Documentation Mistakes

### Insufficient Evidence
Missing hostname verification, cropped screenshots hiding important context, no command shown only output, wrong user context not visible. These are the most common reasons for point deductions.

### Technical Issues
Blurry or unreadable screenshots, missing timestamps when required, incorrect flag content from copy/paste errors, missing system information context. Always verify screenshots are clear before moving on.

### Organizational Problems
Poor file naming making it impossible to identify which machine, missing screenshots for critical steps, inconsistent documentation between machines, no backup of evidence files. Create backups throughout the exam.

## Proof Collection Workflow

1. Capture initial access with screenshot
2. Immediately verify hostname and IP
3. Check current user context with whoami/id
4. Locate and display user flag
5. Screenshot user flag with full context
6. Perform privilege escalation
7. Verify privileged access
8. Locate and display admin/root flag
9. Screenshot admin/root flag with full context
10. Collect system information for documentation

## Time Management for Documentation

### During Exam
Screenshot immediately when something works. Don't wait for perfect screenshots, capture multiple angles if needed. Keep basic notes sufficient during exam, detailed write-up comes later. Focus on getting flags first, perfect documentation second.

### After Exam
Start report writing within 12 hours while memory is fresh. Use templates for consistency across machines. Batch process and organize screenshots. Review everything before final submission.

## Report Structure

Follow the official OffSec report template exactly. Include Executive Summary, Methodology overview, detailed section for each compromised machine, proof screenshots with descriptions, and conclusion. Do not deviate from the template structure.

### Per-Machine Sections

Information Gathering describes enumeration and scanning. Enumeration details service investigation and fingerprinting. Exploitation explains vulnerability identification and exploitation method. Post-Exploitation covers initial access and enumeration. Privilege Escalation details the escalation vector and exploitation. Proof section includes both user and admin/root flags with screenshots.

## Point Calculation Verification

Before finishing exam, verify you have at least 70 points. Count each user flag and admin/root flag. Ensure you have valid proof screenshots for all counted points. Double-check flag content accuracy. Missing or invalid proof means those points don't count.

## Evidence Backup Strategy

Create multiple copies of all evidence throughout the exam. Back up to cloud storage (encrypted) during breaks. Keep local backup on external drive. Generate hash verification of critical screenshots. Never rely on single copy of evidence.

## Post-Submission

Keep all evidence until you receive exam results. Maintain backups in case of submission issues. Document any technical problems encountered. Save successful methodologies for future reference.

## Success Metrics

All flags captured with valid proof screenshots. Complete evidence trail clearly documented. Report submitted before 24-hour deadline. Minimum 70 points achieved with proper documentation. Remember: documentation proves you did the work and makes the difference between pass and fail.
