# OSCP Command Reference

## Getting started
Clone this repository locally and open it in [Obsidian](https://obsidian.md/) for the best experience.

See `Templates/`. Make a copy of `IP Hostname (OpIndex).md` for each machine, and one copy of `AD Domain.md` for Active Directory labs.

For each machine, start in [[Service Discovery]], and enumerate services from the notes in `Runbooks/Services`. After gaining initial access, use the relevant privilege escalation note. If you get admin/root, do the post-exploitation sections in the privesc notes before pivoting with [[Tunneling]].

If the machine is part of a larger network or domain, use [[Active Directory]] and [[AD Domain (OpIndex)]].

Use [[Shell Delivery and Transfer]] for your standard handler, ports, shell payloads, and file transfer workflow.

Notes in the Runbooks folder are formatted for OpIndex.
