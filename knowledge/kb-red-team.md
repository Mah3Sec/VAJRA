# KB: Red Team Operations & Adversary Emulation
# Applies to: Red team, purple team, TIBER-EU, adversary simulation, post-exploitation

## MITRE ATT&CK v14 — Key Tactics & Techniques
| Tactic | ID | Key Techniques |
|---|---|---|
| Reconnaissance | TA0043 | T1595 Active Scan, T1596 Search Open Sources, T1598 Phishing for Info |
| Resource Development | TA0042 | T1583 Acquire Infra, T1585 Establish Accounts, T1587 Develop Capabilities |
| Initial Access | TA0001 | T1566 Phishing, T1190 Exploit Public App, T1078 Valid Accounts, T1195 Supply Chain |
| Execution | TA0002 | T1059 Command Scripting, T1106 Native API, T1053 Scheduled Task |
| Persistence | TA0003 | T1547 Boot Autostart, T1053 Scheduled Task, T1136 Create Account, T1543 Services |
| Privilege Escalation | TA0004 | T1055 Process Injection, T1068 Exploit Privilege, T1548 Bypass UAC |
| Defense Evasion | TA0005 | T1027 Obfuscated Files, T1055 Process Injection, T1562 Impair Defenses |
| Credential Access | TA0006 | T1003 OS Credential Dump, T1110 Brute Force, T1558 Kerberoasting |
| Discovery | TA0007 | T1082 System Info, T1083 File Discovery, T1018 Remote System Discovery |
| Lateral Movement | TA0008 | T1021 Remote Services, T1550 Use Alt Auth, T1534 Internal Spearphishing |
| Collection | TA0009 | T1005 Local Data, T1039 Network Share Data, T1113 Screen Capture |
| Command & Control | TA0011 | T1071 App Layer Protocol, T1573 Encrypted Channel, T1090 Proxy |
| Exfiltration | TA0010 | T1048 Exfil Over Alt Protocol, T1041 Exfil Over C2, T1567 Exfil to Web |
| Impact | TA0040 | T1486 Data Encrypted (ransomware sim), T1485 Data Destruction |

## Red Team Tooling Reference
| Category | Tool | Purpose | Detection Evasion Notes |
|---|---|---|---|
| C2 Framework | Cobalt Strike | Full-featured C2, Beacon implant | Profile customisation, malleable C2 |
| C2 Framework | Havoc | Open-source CS alternative | Custom agent signatures |
| C2 Framework | Sliver | MTLS/WireGuard C2, multi-platform | Built-in traffic obfuscation |
| C2 Framework | Brute Ratel C4 | EDR-focused evasion | Process injection focus |
| Phishing | GoPhish | Phishing campaign management | — |
| Phishing | Evilginx3 | AiTM phishing proxy, MFA bypass | Session cookie capture |
| Credential | Mimikatz | Credential dump (LSASS) | Heavily signatured — use variants |
| Credential | Rubeus | Pure .NET Kerberos abuse | In-memory, less detected |
| Enumeration | BloodHound/SharpHound | AD attack path mapping | LDAP queries — blend with normal traffic |
| Enumeration | PowerView | AD enumeration | PowerShell AMSI bypass needed |
| Network | Responder | LLMNR/NBT-NS poisoning | Detection: LLMNR disable in alerts |
| Post-Exploit | CrackMapExec | SMB/LDAP/WMI Swiss Army knife | Common — use stealth flags |

## Initial Access Techniques — Success Rates & Indicators
| Technique | Typical Success Rate | Key Indicator for Blue Team |
|---|---|---|
| Spear phishing with macro | 15–30% click, 40–60% execution | Outlook spawning cmd/powershell |
| Spear phishing with HTML smuggling | 20–40% execution | Browser spawning child process |
| Password spraying (valid accounts) | 5–15% per spray | Multiple failed auths from one IP |
| Credential stuffing (leaked creds) | 1–5% | Geographically impossible logins |
| VPN brute force | Low without lockout bypass | Auth failures on VPN gateway |
| Exploiting public-facing app | CVE-dependent | WAF alerts, exploit signatures |

## C2 Infrastructure Operational Security
- Domain fronting via CDN (Cloudflare/Fastly) to hide true C2 IP
- Beacon sleep: 60min + 20% jitter in production mode
- HTTPS with valid TLS cert (Let's Encrypt) on domain aged 30+ days
- Categorised domain (financial/tech) to bypass proxy categorisation
- HTTP/HTTPS profiles that blend with legitimate application traffic
- DNS beaconing as fallback (low-and-slow, ~4hr intervals)

## Purple Team — Detection Coverage Assessment
For each ATT&CK technique tested, record:
- Was it detected? (Yes / No / Partial)
- Detection control that fired (SIEM rule / EDR alert / SOC analyst)
- Time to detection (MTTD)
- Time to response (MTTR)
- Detection gap root cause (no visibility / no rule / alert fatigue / analyst missed)
- Recommended detection: SIEM rule name / EDR policy / log source required

## Engagement Metrics — Standard Red Team KPIs
| Metric | Definition | Target (Mature Org) |
|---|---|---|
| MTTIA | Mean time to initial access from first contact | < 4 hours (realistic) |
| MTTCJ | Mean time to crown jewel from initial access | Varies by network segmentation |
| MTTD | Mean time to detect (blue team) | < 1 hour |
| MTTR | Mean time to respond | < 4 hours |
| Detection Rate | % of red team actions detected | > 70% (mature) |
| Dwell Time | Time operating before detection | < 24 hours (mature) |
