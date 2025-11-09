## Perform DNS reverse lookup
```bash
dig -p 53 -x $IP @$IP
```

## Attempt DNS zone transfer
```bash
# dig method OR dnsrecon for automation
dig @$IP -t AXFR domain.local
```

## Run standard dnsrecon scan
```bash
dnsrecon -d domain.local -t std -n $IP
```

## Brute force subdomains with dnsrecon
```bash
dnsrecon -d domain.local -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t brt -n $IP
```

## Query specific DNS record types
```bash
# Change record type: A, MX, TXT, NS, OR ANY for all records
dig @$IP domain.local A
```

---

# DNS Enumeration Methodology

## Initial Reconnaissance

1. Identify DNS server version (may reveal vulnerabilities)
2. Attempt zone transfer (AXFR) - most critical misconfiguration
3. Enumerate DNS records for information gathering
4. Brute force subdomains if zone transfer fails
5. Check for DNS cache snooping

## Zone Transfer Attacks

**Why zone transfers matter:**
A successful zone transfer reveals:
- All hostnames in the domain
- IP addresses of internal systems
- Mail servers and their priorities
- Name servers
- Service records (SRV)
- Complete network topology

## Subdomain Enumeration

When zone transfer fails, brute force subdomains.

**Wordlists:**
- /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt (faster)
- /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt (comprehensive)
- /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt

## Reverse DNS Lookup

Use reverse lookups to:
- Discover hostnames from IP ranges
- Identify internal naming conventions
- Find additional targets in the network

Perform reverse lookups on entire subnets to build target list.

## DNS Cache Snooping

Check if DNS server has cached specific domains:
```bash
dig @$IP target-domain.com +norecurse
```

If it returns a result, the domain was recently queried, revealing browsing habits.

---

# References

- https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns
- https://github.com/darkoperator/dnsrecon
