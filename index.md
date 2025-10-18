# OSCP Methodology & Command Reference

Comprehensive OSCP penetration testing notes optimized for quick command reference during exams.

## Quick Start

**Start Here:** [Service Discovery](Service Discovery.md)

This repository contains both copy-paste ready commands (vClip-indexed) and detailed methodology (for manual reference).

## Per-Machine Template

Use this template structure for each target during the exam:

### Host Information
- Target IP:
- Operating System:
- Domain/Hostname:
- Difficulty:
- Start Time:

### Summary of Findings

#### Domain/Host Name
Add to /etc/hosts:
```

```

#### Vulnerabilities and Suggested Remediation
-

#### Flags
```

```

#### Hashes
```

```

#### Credentials
```

```

---

## Structure

### Initial Discovery
- [Service Discovery](Service Discovery.md) - Port scanning and initial enumeration

### Service-Specific Enumeration
- [FTP (20, 21)](Service Enumeration/20,21 FTP.md)
- [SSH (22)](Service Enumeration/22 SSH.md)
- [SMTP (25, 587)](Service Enumeration/25,587 SMTP.md)
- [DNS (53)](Service Enumeration/53 DNS.md)
- [HTTP/HTTPS (80, 443)](Service Enumeration/80, 443 HTTP.md)
- [Kerberos (88)](Service Enumeration/88 Kerberos.md)
- [MSRPC (135)](Service Enumeration/135 WMI,MSRPC.md)
- [SMB (139, 445)](Service Enumeration/139,445 SMB.md)
- [SNMP (161)](Service Enumeration/161 SNMP.md)
- [LDAP(S) (389, 636)](Service Enumeration/389,636 LDAP(S).md)
- [MSSQL (1433)](Service Enumeration/1433 MSSQL.md)
- [NFS (2049)](Service Enumeration/2049 NFS.md)
- [MySQL (3306)](Service Enumeration/3306 MySQL.md)
- [RDP (3389)](Service Enumeration/3389 RDP.md)
- [WinRM (5985, 5986)](Service Enumeration/5985, 5986 WinRM.md)

### Privilege Escalation
- [Linux Privilege Escalation](Local Privilege Escalation/Linux Privilege Escalation.md)
- [Windows Privilege Escalation](Local Privilege Escalation/Windows Privilege Escalation.md)

### Active Directory
- [Active Directory Enumeration](Active Directory/Active Directory Enumeration.md)
- [Active Directory Attack Chain](Active Directory/Active Directory Attack Chain.md)

### Additional Techniques
- [File Transfer Techniques](Additional Notes/File Transfer Techniques.md)
- [Tunneling](Additional Notes/Tunneling.md)
- [SQL Injection](Additional Notes/SQL Injection.md)
- [Evidence Collection & Reporting](Additional Notes/Evidence Collection & Reporting.md)
- [OSCP Exam Strategy](Additional Notes/OSCP Exam Strategy.md)
- [LLM Usage Guidelines](Additional Notes/LLM.md)

## Exam Day Workflow

1. Start with [Service Discovery](Service Discovery.md) for initial enumeration
2. Follow service-specific guides based on open ports
3. Use privilege escalation guides after initial access
4. For AD environments, use the AD attack chain methodology
5. Reference additional techniques as needed
6. Use [Evidence Collection](Additional Notes/Evidence Collection & Reporting.md) throughout

## Using These Notes

### With vClip (Recommended for Exam)
Quick command access via fuzzy search:
```bash
# Install and configure vClip
cd vClip
pipx install .
vclip --create-config

# Edit ~/.config/vclip/config.yaml to add this directory
# Then use during exam:
vclip  # Opens rofi for instant command search
```

### Manual Reference
All files work as standard markdown with both commands and methodology sections.

## vClip Format

These notes are optimized for vClip:
- **H1**: Category/Service name
- **H2**: Command description (vClip-indexed for fuzzy search)
- **Code blocks**: Copy-paste ready commands
- **Content below `---`**: Methodology and explanations (not indexed by vClip)

See [vClip/README.md](vClip/README.md) for full documentation.

## Credits & Resources

- GTFOBins: https://gtfobins.github.io/
- HackTricks: https://book.hacktricks.xyz/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- LOLBAS Project: https://lolbas-project.github.io/
- BloodHound Documentation: https://bloodhound.readthedocs.io/
- OSCP Secret Sauce: https://eins.li/posts/oscp-secret-sauce/
