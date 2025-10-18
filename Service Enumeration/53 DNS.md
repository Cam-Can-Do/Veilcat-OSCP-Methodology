# DNS Enumeration (53)

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

## Simple DNS query
```bash
# host (simpler) OR nslookup (interactive) OR dig (detailed)
host domain.local $IP
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

**Testing for zone transfer:**
If AXFR succeeds, you get complete domain information without needing to brute force. This is a critical misconfiguration that should always be tested.

## DNS Record Types

**A records:** Hostname to IPv4 address mapping
**AAAA records:** Hostname to IPv6 address mapping
**MX records:** Mail server records (shows email infrastructure)
**TXT records:** Text records (may contain SPF, DKIM, or sensitive info)
**NS records:** Name server records
**CNAME records:** Canonical name (alias) records
**PTR records:** Reverse DNS lookup (IP to hostname)
**SRV records:** Service records (shows available services)
**SOA records:** Start of Authority (domain metadata)

## Subdomain Enumeration

When zone transfer fails, brute force subdomains:

**Common subdomains to look for:**
- mail.domain.local
- ftp.domain.local
- vpn.domain.local
- admin.domain.local
- dev.domain.local
- test.domain.local
- staging.domain.local
- portal.domain.local

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

## DNS Tunneling Detection

Look for signs of DNS tunneling (data exfiltration via DNS):
- Excessive DNS queries
- Unusually long DNS query names
- High entropy in subdomain names
- Queries to suspicious TLDs

## Information in TXT Records

TXT records often contain:
- SPF records (authorized mail servers)
- DKIM keys (email authentication)
- Domain verification tokens
- Configuration information
- Sometimes credentials (rare but happens)

## DNS Enumeration Tools

**dig:** Manual DNS queries, most flexible
**dnsrecon:** Automated enumeration with multiple scan types
**dnsenum:** Comprehensive DNS enumeration
**fierce:** Subdomain brute forcing
**host:** Simple DNS lookups
**nslookup:** Interactive DNS queries

## Common DNS Misconfigurations

1. **Zone transfer allowed to any IP**
2. **Recursive queries enabled for external IPs**
3. **DNS cache poisoning possible**
4. **Outdated BIND versions with known CVEs**
5. **DNS amplification attacks possible**

## Active Directory DNS

In AD environments, DNS is critical:
- Domain controllers register as _ldap._tcp.dc._msdcs.domain
- Find DCs via SRV records: dig @$IP _ldap._tcp.dc._msdcs.domain.local SRV
- Kerberos: _kerberos._tcp.domain.local
- Global catalog: _gc._tcp.domain.local

## Next Steps

Once DNS enumeration is complete:
1. Document all discovered hostnames and IPs
2. Add findings to /etc/hosts for name resolution
3. Scan discovered hosts for open ports
4. Prioritize targets (mail servers, VPN, admin portals)
5. Use discovered subdomains for web enumeration

---

# References

- https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns
- https://github.com/darkoperator/dnsrecon
