# Enumeration
## nmap RPC scripts
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

## RID brute force / cycling with netexec
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

## RID Cycling Attack

**What is RID cycling:**
Relative Identifiers (RIDs) are sequential numbers assigned to user and group objects. By querying RIDs sequentially, you can discover all users and groups.

## WMI Enumeration

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

---

# References

- https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc
- https://github.com/SecureAuthCorp/impacket
- https://0xdf.gitlab.io/cheatsheets/rpc-enum
