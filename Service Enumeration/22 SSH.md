## nmap SSH enumeration scripts
```bash
nmap --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 $IP
```

## Audit SSH configuration with ssh-audit
```bash
ssh-audit $IP -p 22
```

## Convert SSH key to John format for cracking
```bash
ssh2john id_rsa > id_rsa.hash
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
## SSH Authorized Keys

If you can write to ~/.ssh/authorized_keys:
```bash
echo "your_public_key" >> ~/.ssh/authorized_keys
```

This gives persistent SSH access without password.

## SSH Tunneling

**Local Port Forward:**
Forward local port to remote service through SSH tunnel. Useful for accessing internal services.

**Dynamic Port Forward (SOCKS):**
Creates SOCKS proxy for routing traffic through SSH. Configure proxychains to use 127.0.0.1:9050.

**Remote Port Forward:**
Forward remote port back to attacker machine. Useful for reverse tunnels from restricted networks.

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


---

# References

- https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh
