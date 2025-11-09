# SNMP Enumeration (161)

## Run nmap SNMP scripts
```bash
nmap -sU -p 161 --script=snmp-* $IP
```

## Walk SNMP with community string
```bash
# -c public OR -c private; -v1 OR -v2c for version
snmpwalk -c public -v1 $IP
```

## Brute force community strings
```bash
# onesixtyone (faster) OR hydra (more reliable)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $IP
```

## Get system description via SNMP
```bash
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.1.1.0
```

## Get system uptime via SNMP
```bash
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.1.3.0
```

## Get system name via SNMP
```bash
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.1.5.0
```

## Get network interfaces via SNMP
```bash
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.2.2.1.2
```

## Get routing table via SNMP
```bash
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.4.21.1.1
```

## Get ARP table via SNMP
```bash
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.4.22.1.2
```

## Get Windows users via SNMP
```bash
snmpwalk -c public -v1 $IP 1.3.6.1.4.1.77.1.2.25
```

## Get running processes via SNMP
```bash
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.4.2.1.2
```

## Get installed software via SNMP
```bash
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.6.3.1.2
```

## Get TCP connections via SNMP
```bash
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.6.13.1.3
```

## Run snmpcheck for comprehensive enumeration
```bash
snmpcheck -t $IP -c public
```

## Test SNMP SET operations
```bash
snmpset -c private -v1 $IP 1.3.6.1.2.1.1.4.0 s "Pwned"
```

---

# SNMP Enumeration Methodology

## Initial Reconnaissance

1. Confirm SNMP service is running (UDP 161)
2. Test default community strings (public, private, manager)
3. If defaults fail, brute force community strings
4. Once valid string found, enumerate system information
5. Focus on Windows-specific OIDs for user/process/software data

## Community String Testing

**Default community strings:**
- public (read-only, most common)
- private (read-write, less common)
- manager (administrative access)

**Try both SNMPv1 and SNMPv2c:**
Some systems only respond to specific SNMP versions.

## Community String Brute Force

**When to brute force:**
- Default strings don't work
- SNMP is critical to engagement
- Other enumeration methods exhausted

**Tools:**
- onesixtyone: Fast, efficient
- hydra: Slower but reliable

**Best wordlist:**
/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt

## System Information OIDs

**Basic system info:**
- 1.3.6.1.2.1.1.1.0: System description
- 1.3.6.1.2.1.1.3.0: System uptime
- 1.3.6.1.2.1.1.4.0: System contact
- 1.3.6.1.2.1.1.5.0: System name
- 1.3.6.1.2.1.1.6.0: System location

This reveals OS version, hostname, and uptime.

## Network Information OIDs

**Interfaces and routing:**
- 1.3.6.1.2.1.2.2.1.2: Network interfaces
- 1.3.6.1.2.1.4.21.1.1: Routing table
- 1.3.6.1.2.1.4.22.1.2: ARP table
- 1.3.6.1.2.1.6.13.1.3: TCP connections
- 1.3.6.1.2.1.7.5.1.2: UDP connections

**What this reveals:**
- Network topology
- Internal IP addresses
- Connected systems
- Active connections

## Windows-Specific OIDs

**User enumeration:**
- 1.3.6.1.4.1.77.1.2.25: Windows users
- 1.3.6.1.4.1.77.1.2.25.1.1: User account names

**Running processes:**
- 1.3.6.1.2.1.25.4.2.1.2: Process names
- 1.3.6.1.2.1.25.4.2.1.4: Process paths

**Installed software:**
- 1.3.6.1.2.1.25.6.3.1.2: Software names

**Network shares:**
- 1.3.6.1.4.1.77.1.2.3.1.1: Share names
- 1.3.6.1.4.1.77.1.2.27.1.1: Share paths

**Storage information:**
- 1.3.6.1.2.1.25.2.3.1.3: Storage units
- 1.3.6.1.2.1.25.2.3.1.5: Storage sizes

## SNMP Versions

**SNMPv1:**
- Oldest, least secure
- Plaintext community strings
- No authentication beyond community string

**SNMPv2c:**
- Improved performance
- Still uses community strings
- Most commonly deployed

**SNMPv3:**
- Adds authentication and encryption
- Rarely seen in pentests
- Much more secure

## snmpcheck Tool

**Why use snmpcheck:**
- Automated comprehensive enumeration
- Parses OIDs into readable format
- Saves time vs manual snmpwalk

**Output includes:**
- System information
- User accounts
- Network configuration
- Running processes
- Installed software
- Network shares

## SNMP SET Operations

**If write community string found:**
- Can modify system configuration
- Test with non-destructive change first
- Potential for exploitation

**Common write strings:**
- private
- write
- admin

**Be careful:** SET operations can disrupt systems.

## Information Disclosure Risks

**Sensitive data via SNMP:**
- Usernames (for password attacks)
- Network topology (for lateral movement)
- Running services (for exploit targeting)
- Software versions (for CVE matching)
- Active connections (for pivoting)

## Attack Workflow

1. Test default community strings
2. Brute force if needed
3. Get system info to identify OS
4. If Windows, enumerate users and processes
5. Map network topology (routing, ARP)
6. Document software versions
7. Look for credentials in process lists
8. Identify internal services for pivoting

## Common Ports

- 161/udp: SNMP
- 162/udp: SNMP trap (notifications)
- 10161/tcp: SNMP over TLS (rare)

## Enumeration Checklist

- [ ] Test default community strings
- [ ] Brute force if defaults fail
- [ ] System information gathering
- [ ] Network topology enumeration
- [ ] Windows user enumeration (if applicable)
- [ ] Process and software enumeration
- [ ] Network share discovery
- [ ] Connection state analysis
- [ ] SET operation testing (if write access)

## Common Misconfigurations

1. **Default community strings** still in use
2. **SNMP accessible from external networks**
3. **Write community strings** with weak values
4. **SNMPv1/v2c instead of v3** (no encryption)
5. **Excessive information disclosure** via SNMP

## Next Steps

Once SNMP enumeration is complete:
1. Cross-reference discovered users with other services
2. Use network topology for lateral movement planning
3. Match software versions to known vulnerabilities
4. Look for credentials in process command lines
5. Correlate share names with SMB enumeration

---

# References

- https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp
- http://www.oid-info.com/ (OID reference)
- http://www.ireasoning.com/mibbrowser.shtml (MIB browser)
