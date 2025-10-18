# OSCP Methodology & Command Reference

Comprehensive OSCP penetration testing notes optimized for quick command reference during exams.

## Quick Start

**Start Here:** [[Service Discovery]]

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
- [[Service Discovery]] - Port scanning and initial enumeration

### Service-Specific Enumeration

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

## Using These Notes

### With vClip (Recommended for Exam)
Quick command access via fuzzy search:
```bash
# Install and configure vClip
cd vClip
pipx install .
vclip --create-config

# Edit ~/.config/vclip/config.yaml to add this template directory
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
