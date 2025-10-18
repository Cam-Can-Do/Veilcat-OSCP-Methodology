# SSH Enumeration (22)

## Run nmap SSH enumeration scripts
```bash
nmap --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 $IP
```

## Grab SSH banner with netcat
```bash
nc -nv $IP 22
```

## Audit SSH configuration with ssh-audit
```bash
ssh-audit $IP -p 22
```

## Test SSH login with username
```bash
ssh user@$IP
```

## Connect with SSH key
```bash
ssh -i id_rsa user@$IP
```

## Set correct permissions on SSH private key
```bash
chmod 600 id_rsa
```

## Convert SSH key to John format for cracking
```bash
ssh2john id_rsa > id_rsa.hash
```

## Crack encrypted SSH key with John
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

## Brute force SSH with hydra (use sparingly)
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://$IP -t 4
```

## Create local port forward via SSH
```bash
ssh -L 8080:192.168.1.20:80 user@$IP
```

## Create dynamic SOCKS proxy via SSH
```bash
ssh -D 9050 user@$IP
```

## Create remote port forward via SSH
```bash
ssh -R 8080:127.0.0.1:80 user@$IP
```

---

# SSH Enumeration Methodology

## Initial Reconnaissance

1. Identify SSH version from banner
2. Check for known vulnerabilities in that version
3. Enumerate supported algorithms (weak crypto)
4. Test for username enumeration
5. Attempt common credentials
6. Check for SSH keys in other services

## Common Default Credentials

Try these if no other credentials found:
- root:root
- root:toor
- admin:admin
- pi:raspberry (Raspberry Pi)
- ubuntu:ubuntu
- user:user

## Username Enumeration

Some older SSH implementations leak valid usernames through timing attacks or error messages. Test with:
```bash
ssh -o PreferredAuthentications=none username@$IP
```

Look for different responses for valid vs invalid users.

## SSH Key Discovery

Look for SSH keys in:
- Web directories exposed via HTTP/FTP
- User home directories on file shares (SMB/NFS)
- Backup files
- Git repositories
- Common paths: .ssh/id_rsa, .ssh/id_dsa, .ssh/id_ecdsa, .ssh/id_ed25519

## SSH Key Permissions

SSH requires strict permissions on private keys:
```bash
chmod 600 id_rsa      # Private key must be 600
chmod 644 id_rsa.pub  # Public key can be 644
```

## Cracking Encrypted Keys

If SSH key is password-protected:
1. Convert to hash format with ssh2john
2. Crack with John the Ripper or hashcat
3. Use cracked password to decrypt key

## SSH Tunneling

**Local Port Forward:**
Forward local port to remote service through SSH tunnel. Useful for accessing internal services.

**Dynamic Port Forward (SOCKS):**
Creates SOCKS proxy for routing traffic through SSH. Configure proxychains to use 127.0.0.1:9050.

**Remote Port Forward:**
Forward remote port back to attacker machine. Useful for reverse tunnels from restricted networks.

## SSH Configuration Analysis

If you gain access, check /etc/ssh/sshd_config for:
- PermitRootLogin yes (allows root login)
- PasswordAuthentication yes (allows password auth)
- PermitEmptyPasswords yes (critical vulnerability)
- X11Forwarding yes (may allow GUI app tunneling)
- AllowUsers/DenyUsers (access control lists)

## Weak Algorithms

ssh-audit will identify weak or deprecated algorithms:
- 3DES encryption (deprecated)
- MD5 HMAC (weak)
- SHA-1 HMAC (weak)
- CBC mode ciphers (vulnerable to attacks)

## Known SSH CVEs

- CVE-2018-15473: Username enumeration timing attack
- CVE-2020-15778: Command injection via scp
- CVE-2021-41617: Privilege escalation
- CVE-2016-20012: MaxAuthTries bypass

Check discovered version against CVE databases.

## Brute Force Considerations

**Only use brute force when:**
- No other options available
- Small, targeted username/password lists
- Account lockout policy is known

**Recommendations:**
- Use -t 4 flag to limit threads (avoid overwhelming service)
- Start with top 100 passwords, not entire rockyou.txt
- Try password spraying (one password, many users) instead

## SSH Authorized Keys

If you can write to ~/.ssh/authorized_keys:
```bash
echo "your_public_key" >> ~/.ssh/authorized_keys
```

This gives persistent SSH access without password.

## Restricted Shell Escape

If you land in a restricted shell (rbash, rksh):
- Try SSH escape sequences: ~C then -L for port forward
- Abuse allowed commands: vi, less, more, man (then :!/bin/bash)
- Check environment variables for shell bypass

## SSH Agent Hijacking

If SSH agent forwarding is enabled (ForwardAgent yes), you can hijack the agent socket to authenticate as the original user:
```bash
SSH_AUTH_SOCK=/tmp/ssh-agent-socket ssh user@target
```

## Next Steps

Once SSH access is obtained:
1. Enumerate system for privilege escalation
2. Check sudo permissions: sudo -l
3. Look for SUID binaries: find / -perm -4000 2>/dev/null
4. Search for credentials in home directories
5. Check for other users and their files
6. Setup persistence if needed

---

# References

- https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh
- https://stribika.github.io/2015/01/04/secure-secure-shell.html
- https://www.ssh.com/academy/ssh/tunneling
