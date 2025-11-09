# Active Directory Attack Reference

Extended AD methodology reference. For core commands, see [[Active Directory]]. For systematic credential testing, use [[CHECKLIST-AD-Domain]].

## Attack Chain Decision Trees

**If Anonymous LDAP Succeeds:**
1. Extract all users and computers
2. Immediately try ASREPRoasting
3. Password spray with top 3 passwords
4. Proceed to authenticated enumeration

**If Anonymous Access Fails:**
1. Try ASREPRoast with guessed common usernames (administrator, admin, guest)
2. Check for default credentials
3. Look for web applications with AD integration
4. Consider Responder if on internal network

**If Password Spraying Succeeds:**
1. Immediately validate credentials on multiple services (SMB, WinRM, LDAP, MSSQL)
2. Run BloodHound collection
3. Kerberoast service accounts
4. Check for WinRM/RDP access

**If Service Account Compromised:**
1. Test for admin privileges on other systems
2. Check for delegation opportunities
3. Look for SPN permission abuse
4. Attempt lateral movement

## Common Attack Combinations

**LDAP -> ASREPRoast -> WinRM Chain:**
1. Anonymous LDAP enumeration for users
2. ASREPRoast discovered users
3. Crack hashes offline
4. Login via WinRM with cracked credentials

**SMB -> Password Spray -> Kerberoast Chain:**
1. SMB null session for user enumeration
2. Password spray with common passwords
3. Kerberoast service accounts with valid creds
4. Crack service hashes for privilege escalation

**Responder -> Relay -> Secretsdump Chain:**
1. Capture credentials with Responder
2. Relay to targets without SMB signing
3. Gain local admin access
4. Extract credentials for lateral movement

## BloodHound Priority Analysis

**Immediate Wins:**
1. Shortest path to Domain Admins
2. Users with DCSync rights
3. Service accounts with admin access
4. Kerberoastable accounts with privileges

**Medium Effort Paths:**
1. GenericAll/WriteDacl on high-value objects
2. Computers with unconstrained delegation
3. Group Policy abuse opportunities
4. Weak ACLs on sensitive groups

## Common Pitfalls

**Account Lockout:**
- Always check password policy before spraying (`--pass-pol`)
- Use delay between spray attempts
- Test on small user subset first

**Noise Generation:**
- Don't enumerate all shares on all systems
- Focused enumeration over broad scanning
- Use BloodHound instead of brute force

**Missing Opportunities:**
- Always try ASREPRoasting even without user list
- Check for null sessions on all protocols (SMB, LDAP, RPC)
- Don't skip BloodHound collection

## Tool Selection Guidelines

**Anonymous Enumeration:**
- `ldapsearch` for LDAP (lightweight, quiet)
- `enum4linux-ng` for comprehensive SMB/RPC/LDAP
- `netexec` for quick null session testing

**Credential Attacks:**
- `impacket-GetNPUsers` for ASREPRoasting
- `netexec` for password spraying (supports multiple protocols)
- `hashcat` for hash cracking

**Authenticated Enumeration:**
- `bloodhound-python` from Kali (stealthy)
- `SharpHound.exe` on Windows (comprehensive)
- `PowerView` for Windows-side enumeration

**Lateral Movement:**
- `evil-winrm` for interactive shells
- `netexec` for credential testing
- `impacket` suite for targeted attacks

## Time Management

**First 30 Minutes (Critical Window):**
- Test anonymous enumeration across all AD services (LDAP, SMB, RPC)
- Compile comprehensive user list
- Start ASREPRoast attack
- Password spray with top 5 common passwords

**Next 30 Minutes (Exploitation):**
- Run BloodHound if credentials obtained
- Kerberoast service accounts
- Start hash cracking in background
- Analyze BloodHound paths

**Ongoing (Escalation):**
- Monitor hash cracking progress
- Test cracked credentials immediately
- Pursue identified BloodHound paths
- Lateral movement to high-value targets

## Resources

- BloodHound Usage: https://bloodhound.readthedocs.io/
- Impacket Examples: https://github.com/SecureAuthCorp/impacket/tree/master/examples
- AD Security: https://adsecurity.org/
- HackTricks AD: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- BloodHound Attack Paths: https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/
