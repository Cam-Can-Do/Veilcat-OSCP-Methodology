# Initial Service Discovery

## Quick setup - Create working directories from hosts.txt
```bash
export IP=$IP
mkdir -p $IP/{nmap,web,exploit,loot}
cd $IP
```

## Run AutoRecon for automated enumeration
```bash
autorecon $IP --only-scans-dir
```

## Fast TCP port discovery with nmap
```bash
nmap --min-rate 4500 --max-rtt-timeout 1500ms -p- -Pn $IP -oG nmap/all_ports.gnmap
```

## Nmap open TCP ports to markdown checklist
```bash
TCP_PORTS=$(grep -oP '\d+/open' nmap/all_ports.gnmap | cut -d/ -f1 | sed 's/^/- \[\ \]\ /')
echo "TCP:\n$TCP_PORTS"
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
