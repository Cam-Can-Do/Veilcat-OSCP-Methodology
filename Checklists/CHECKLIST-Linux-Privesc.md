# Linux Privilege Escalation Checklist

**DO NOT SKIP STEPS.** Check every box in order. This prevents missing obvious vectors.

## Initial Enumeration (Always Run First)

- [ ] Run LinPEAS: [[Linux Privilege Escalation#LinPEAS (Kali Source)|LinPEAS (Kali Source)]]
- [ ] Run basic context: `id`, `whoami`, `hostname`, `uname -a`
- [ ] Check sudo rights: `sudo -l`
- [ ] Check SUID binaries: [[Linux Privilege Escalation#Find SUID files|Find SUID files]]
- [ ] List cronjobs: `cat /etc/crontab` and `ls -la /etc/cron.*`
- [ ] Check writable paths: [[Linux Privilege Escalation#Find writable directories|Find writable directories]]

## Credential Hunting (Even If You Already Have Access)

**DO NOT ASSUME you found all credentials. Always check:**

- [ ] Search for backup files: [[Linux Privilege Escalation#Find backup files|Find backup files]]
- [ ] Check bash history: [[Linux Privilege Escalation#Check bash history|Check bash history]]
- [ ] Search for passwords in /etc: [[Linux Privilege Escalation#grep etc for password|grep etc for password]]
- [ ] Search webroot for passwords: [[Linux Privilege Escalation#grep webroot for password|grep webroot for password]]
- [ ] Check for private keys: [[Linux Privilege Escalation#grep for private keys|grep for private keys]]
- [ ] Check application configs: [[Linux Privilege Escalation#Check application configs|Check application configs]]

## Quick Win Checks (High Priority)

- [ ] GTFOBins sudo: If `sudo -l` shows anything, check https://gtfobins.github.io/
- [ ] Writable /etc/passwd: `ls -la /etc/passwd` (if writable, add root user)
- [ ] Docker group: If `id` shows docker group, use [[Linux Privilege Escalation#Docker escape to host|Docker escape to host]]
- [ ] LXD/LXC group: If in lxd group, exploit container escape
- [ ] Kernel exploits: Check `uname -r` against known exploits (last resort - can crash system)

## Service/Application Enumeration

- [ ] List running processes: `ps auxww` (look for root processes with writable binaries)
- [ ] Check listening ports: `ss -tulnp` or `netstat -tulnp` (internal services to enumerate)
- [ ] Check for MySQL/databases running: Test default creds `mysql -u root -p` (try empty password)
- [ ] Web servers running? Check `/var/www`, `/var/www/html` for config files with DB creds

## SUID/Capabilities Exploitation

- [ ] Review SUID binary list for GTFOBins entries
- [ ] Check capabilities: [[Linux Privilege Escalation#Find files with capabilities|Find files with capabilities]]
- [ ] Test writable paths in SUID binary execution (PATH hijacking)

## Cronjob/Scheduled Task Abuse

- [ ] Check if any cronjob scripts are writable: `ls -la /etc/cron.*/`
- [ ] Monitor for cronjobs: `pspy64` (if available) or watch `/var/log/syslog`
- [ ] Check systemd timers: `systemctl list-timers --all`

## NFS/Network Share Checks

- [ ] Check NFS exports: `cat /etc/exports` (no_root_squash = win)
- [ ] Check mounted shares: `mount` and `cat /etc/fstab`

## Post-Root Enumeration (After Getting Root)

**EVEN WITH ROOT, check for useful items for lateral movement:**

- [ ] Dump /etc/shadow: `cat /etc/shadow` (crack for passwords to try elsewhere)
- [ ] Check SSH keys in /root and /home/*: `find /root /home -name id_rsa 2>/dev/null`
- [ ] Search for additional credentials: `grep -r "password" /root /home 2>/dev/null`
- [ ] Check network connections: `ip addr` (additional NICs for pivoting?)
- [ ] Review bash histories for all users: `cat /home/*/.bash_history /root/.bash_history 2>/dev/null`

## Common Pitfalls

**STOP and re-check if stuck for 15+ minutes:**
- Did you run LinPEAS and actually READ the output thoroughly?
- Did you check sudo -l and search GTFOBins?
- Did you search ALL home directories for credentials?
- Did you test found credentials against MySQL/databases?
- Did you check /opt, /var/backups for backup files?

## Reference

For detailed commands, see [[Linux Privilege Escalation]]
