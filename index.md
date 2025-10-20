# OSCP Methodology & Command Reference

Comprehensive OSCP penetration testing notes optimized for quick command reference during exams.

## Quick Start

**Start Here:** [[Service Discovery]]

This repository contains both copy-paste ready commands and detailed methodology for manual reference. 

Commands are formatted to be compatible with [vClip](https://github.com/Cam-Can-Do/vClip), my snippet management utility.

## Note Templates
See the "Note Templates" folder. Make a copy of "IP-Hostname.md" for each machine, and one copy of "AD-Domain.md" for Active Directory labs.

*These templates are minimal by design. They are not meant to be a final report, but rather a lightweight frame for recording steps.*

*Previously I cloned this entire methodology folder for each machine and filled it in with command output as I worked; I found this to be cumbersome, as I didn't always need every command, and ended up deleting more text than I wrote for each machine!*


---
## Using These Notes

### With vClip (Recommended for Exam)
Quick command access via fuzzy search:
```bash
# Install and configure vClip
git clone https://github.com/Cam-Can-Do/vClip
cd vClip
pipx install .
vclip --create-config

# Edit ~/.config/vclip/config.yaml to add this directory, as well as any others of your choosing!
# Then use during exam:
vclip --no-prompt # Opens rofi for instant command search; I recommend binding this to a hotkey.
```

### Manual Reference
All files work as standard markdown with both commands and methodology sections.

## vClip Format

These notes are optimized for vClip:
- **H1**: Category/Service name
- **H2**: Command description (vClip-indexed for fuzzy search)
- **Code blocks**: Copy-paste ready commands
- **Content below `---`**: Methodology and explanations (not indexed by vClip)

## Credits & Resources

- GTFOBins: https://gtfobins.github.io/
- HackTricks: https://book.hacktricks.xyz/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- LOLBAS Project: https://lolbas-project.github.io/
- BloodHound Documentation: https://bloodhound.readthedocs.io/
- OSCP Secret Sauce: https://eins.li/posts/oscp-secret-sauce/
