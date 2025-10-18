# Initial Service Discovery

## Quick setup - Create working directory
```bash
export IP=$IP
export DOMAIN=target.local
mkdir -p $IP/{nmap,web,smb,ftp,exploit,loot}
cd $IP
```

## Run AutoRecon for automated enumeration
```bash
autorecon $IP --only-scans-dir
```

## View AutoRecon full TCP scan results
```bash
cat results/$IP/scans/_full_tcp_nmap.txt
```

## Fast TCP port discovery with nmap
```bash
nmap --min-rate 4500 --max-rtt-timeout 1500ms -p- -Pn $IP -oG nmap/all_ports.gnmap
```

## Extract open TCP ports from nmap scan
```bash
TCP_PORTS=$(grep -oP '\d+/open' nmap/all_ports.gnmap | cut -d/ -f1 | paste -sd, -)
echo "Open TCP ports: $TCP_PORTS"
```

## Run nmap service detection and scripts on open ports
```bash
nmap -sC -sV -T4 -Pn -p $TCP_PORTS $IP -oA nmap/full_tcp
```

## Scan top 100 UDP ports
```bash
nmap -sU --top-ports 100 -T4 -Pn $IP -oA nmap/top_udp
```

## Scan top 1000 UDP ports (extended)
```bash
nmap -sU --top-ports 1000 -T4 -Pn $IP -oA nmap/extended_udp
```

---

# Service Discovery Methodology

## Initial Setup

Before starting enumeration, create a structured workspace:
- Set IP and DOMAIN environment variables
- Create subdirectories for each service type
- Use consistent naming for output files

## AutoRecon vs Manual

**AutoRecon**: Best for comprehensive automated scanning. Use when:
- Time is not critical
- You want comprehensive coverage
- You're multitasking on multiple boxes

**Manual scanning**: Better for:
- Faster initial results
- More control over scan speed/noise
- Understanding what's running before deeper enumeration

## TCP Port Discovery Strategy

Two-phase approach:
1. Fast full port scan to find all open ports
2. Detailed service detection only on open ports

This is faster than running `-sC -sV -p-` directly, especially on boxes with few open ports.

## UDP Scanning Considerations

UDP scanning is slow. Prioritize based on time:
- Top 100 ports: Always run (catches DNS, SNMP, TFTP)
- Top 1000 ports: Run if you have time or suspect UDP services
- Full UDP scan: Rarely worth it in OSCP exam environment

Common critical UDP services:
- 53 (DNS)
- 69 (TFTP)
- 161 (SNMP)
- 500 (IPSec)

## Service Enumeration Priority

After port discovery, enumerate services in this order:

### Critical Services (Immediate Focus)
1. HTTP/HTTPS (80, 443, 8080, 8443)
2. SMB (139, 445)
3. FTP (21)
4. SSH (22)
5. DNS (53)

### Active Directory Services
1. Kerberos (88)
2. LDAP (389, 636)
3. MSRPC (135)
4. WinRM (5985, 5986)

### Database Services
1. MySQL (3306)
2. MSSQL (1433)
3. PostgreSQL (5432)
4. MongoDB (27017)

### Remote Access
1. RDP (3389)
2. VNC (5900+)
3. Telnet (23)

### Other Common Services
- SMTP (25, 587)
- SNMP (161)
- NFS (2049)

## Output File Naming

Use consistent naming:
- `nmap/all_ports.gnmap` - Initial port discovery
- `nmap/full_tcp.*` - Detailed TCP enumeration
- `nmap/top_udp.*` - UDP scan results
- Service-specific: `web/`, `smb/`, `ftp/`, etc.

This makes report writing easier and keeps evidence organized.

## Time Management

**First 15 minutes:**
- Launch AutoRecon in background OR run fast nmap
- While scanning, review nmap results as they come in
- Start web enumeration immediately if HTTP is detected

**Next 30 minutes:**
- Deep dive into highest priority services
- Launch background tasks (directory bruteforce, hash cracking)
- Take notes on findings

## Common Pitfalls

**Skipping UDP**: SNMP and DNS can provide critical enumeration data.

**Not saving output**: Always use `-oA` to save nmap results in all formats.

**Running -sC -sV on all 65535 ports**: Extremely slow. Do fast discovery first.

**Forgetting -Pn**: OSCP machines often don't respond to ping. Always use -Pn.

---

# Service-Specific Enumeration Links

After initial discovery, jump to service-specific enumeration:

- FTP (20, 21): See Service Enumeration/20,21 FTP.md
- SSH (22): See Service Enumeration/22 SSH.md
- DNS (53): See Service Enumeration/53 DNS.md
- HTTP/HTTPS (80, 443): See Service Enumeration/80, 443 HTTP.md
- Kerberos (88): See Service Enumeration/88 Kerberos.md
- MSRPC (135): See Service Enumeration/135 WMI,MSRPC.md
- SMB (139, 445): See Service Enumeration/139,445 SMB.md
- SNMP (161): See Service Enumeration/161 SNMP.md
- LDAP (389, 636): See Service Enumeration/389,636 LDAP(S).md
- MSSQL (1433): See Service Enumeration/1433 MSSQL.md
- NFS (2049): See Service Enumeration/2049 NFS.md
- MySQL (3306): See Service Enumeration/3306 MySQL.md
- RDP (3389): See Service Enumeration/3389 RDP.md
- WinRM (5985, 5986): See Service Enumeration/5985, 5986 WinRM.md
