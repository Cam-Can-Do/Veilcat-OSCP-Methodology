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

## AutoRecon vs Manual

Run manual scans first and start enumerating high priority services while autorecon runs in the background.
## TCP Port Discovery Strategy

Two-phase approach:
1. Fast full port scan to find all open ports
2. Detailed service detection only on open ports

This is faster than running `-sC -sV -p-` directly, especially on boxes with few open ports.

## UDP Scanning Considerations

UDP scanning is slow. Prioritize based on time:
- Top 100 ports: Always run (catches DNS, SNMP, TFTP)
- Top 1000 ports: Run if you have time or suspect UDP services

Common critical UDP services:
- 53 (DNS)
- 69 (TFTP)
- 161 (SNMP)
- 500 (IPSec)

---

# Service-Specific Enumeration Checklist 

After initial discovery, jump to service-specific enumeration in the "Service Enumeration" folder. 
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
