# Network Traffic Analysis: Identifying DoS and Reconnaissance Attacks Using Wireshark

## Overview

A hands-on network security project analyzing real attack traffic using Wireshark. Each capture is examined at the packet level to understand attack mechanics, identify indicators of compromise, and document defensive detection strategies.

This project was built as a self-directed learning exercise to develop practical packet analysis skills — understanding not just *what* malicious traffic looks like, but *why* each attack works at the protocol level and *how* defenders detect it.

## Tools

- Wireshark
- Official Wireshark sample captures (wiki.wireshark.org/SampleCaptures)
- NMap Captures.zip (public sample dataset, included README confirms commands)

## Captures Analyzed

| Capture | Attack Type | Key Concept |
|---|---|---|
| [teardrop-analysis](./teardrop-analysis/teardrop-analysis.md) | Teardrop DoS | Overlapping IP fragments crash kernel reassembly logic |
| [nmap-standard-scan](./nmap-standard-scan/nmap-standard-scan.md) | SYN Port Scan | Automated port discovery via SYN-only probes |
| [nmap-ack-scan-port80](./nmap-ack-scan-port80/nmap-ack-scan-port80.md) | ACK Scan | Stateful firewall detection via out-of-state ACK packets |
| [nmap-ack-scan-evasion](./nmap-ack-scan-evasion/nmap-ack-scan-evasion.md) | ACK + Fragmentation + IP Spoofing | IDS evasion combined with attacker identity concealment |
| nmap-zombie-scan | Idle/Zombie Scan | Complete attacker invisibility via third-party IP ID exploitation |
| nmap-os-scan | Failed OS Fingerprint | OS detection attempt on fully filtered target |
| nmap-os-scan-successful | Successful OS Fingerprint | OS identification via TCP/IP stack response behavior |
| smtp-analysis | Cleartext Credential Interception | Decoding base64 AUTH LOGIN credentials from plaintext SMTP |

## Project Structure

Each folder contains a markdown analysis file and annotated Wireshark screenshots. Every analysis follows this structure:

- Attack context and attacker's goal
- Filters applied and packet-level evidence
- Root cause explanation
- Attacker vs. defender perspective

