# KB: Network & Infrastructure Penetration Testing
# Applies to: External perimeter, internal network, firewall, switches, routers

## Network Testing Phases (NIST SP 800-115 / PTES)
1. Discovery: Host discovery (nmap -sn), port scan (nmap -sS -sV), OS fingerprint
2. Enumeration: Service versions, banner grabbing, SNMP, SMB, LDAP enum
3. Vulnerability Identification: NSE scripts, Nessus, manual verification
4. Exploitation: Controlled PoC — no destructive actions without explicit auth
5. Post-Exploitation: Network pivot, credential reuse, lateral movement assessment
6. Reporting: Evidence, CVSS scoring, remediation deadlines

## Common Network Findings — CVSS & CWE
| Finding | CVSS | CWE | Notes |
|---|---|---|---|
| EternalBlue / MS17-010 (SMBv1) | 9.8 | CWE-119 | Remote unauthenticated RCE |
| BlueKeep / CVE-2019-0708 (RDP) | 9.8 | CWE-416 | Unauthenticated RCE via RDP |
| Default/weak credentials on network device | 9.8 | CWE-798 | Router, switch, firewall admin |
| Open RDP exposed to internet | 8.1 | CWE-284 | Brute-force and lateral movement risk |
| Telnet / unencrypted management | 7.5 | CWE-319 | Cleartext credential interception |
| SNMPv1/v2 with default community string | 7.5 | CWE-798 | Device enumeration and config access |
| Weak SSH configuration (old ciphers) | 5.9 | CWE-326 | Downgrade attack risk |
| NFS share world-readable | 7.5 | CWE-284 | Unauthenticated file system access |
| SMB signing disabled | 5.9 | CWE-294 | NTLM relay attack vector |
| DNS zone transfer allowed | 5.3 | CWE-200 | Internal network topology disclosure |
| Unused open ports (management interfaces) | 3.7 | CWE-16 | Attack surface expansion |
| Split tunneling VPN misconfiguration | 6.5 | CWE-16 | Traffic bypass |
| Firewall rule too permissive (any/any) | 7.5 | CWE-284 | Lateral movement enablement |
| Network device running EOL firmware | 7.5 | CWE-1104 | Unpatched known vulnerabilities |
| VLAN hopping (switch misconfiguration) | 7.5 | CWE-284 | Cross-VLAN unauthorized access |

## Port / Service Risk Matrix
| Port | Service | Risk if Exposed | Test |
|---|---|---|---|
| 21 | FTP | Cleartext, anon login | Banner grab, anon auth, brute |
| 22 | SSH | Brute force, weak config | Cipher check, auth methods |
| 23 | Telnet | Cleartext creds | Banner, default creds |
| 25 | SMTP | Open relay, user enum | VRFY/EXPN, relay test |
| 53 | DNS | Zone transfer, cache poison | AXFR, recursive query |
| 80/443 | HTTP/HTTPS | Web vulns | Web testing KB |
| 135/445 | MSRPC/SMB | EternalBlue, relay | SMB signing, version |
| 161 | SNMP | Config disclosure | Community string, MIB walk |
| 389/636 | LDAP/LDAPS | Null bind, enum | Anonymous bind, enum |
| 1433 | MSSQL | SA account, xp_cmdshell | Default creds, linked servers |
| 3306 | MySQL | Remote root | Default creds, file read |
| 3389 | RDP | BlueKeep, brute | NLA, version, brute |
| 5900 | VNC | No auth, weak password | Auth check, default creds |
| 8080 | Alt HTTP | Admin console | Web testing KB |

## Network Lateral Movement Techniques
- Pass-the-Hash (PtH): NTLM hash reuse without cracking
- Pass-the-Ticket (PtT): Kerberos TGT/TGS reuse
- Overpass-the-Hash: Convert NTLM hash to Kerberos ticket
- NTLM relay (Responder + ntlmrelayx): Capture and relay credentials
- SMB pivot: Use compromised host as jump point
- SSH tunnelling: Forward internal ports through SSH

## Remediation Standards
- Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false
- Enable SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true
- Disable Telnet: Remove telnet service, enforce SSH with strong ciphers
- SNMP: Upgrade to SNMPv3 with auth+encryption; remove community strings
- RDP: Enforce NLA, restrict to VPN/jump host, apply all RDP patches
- Firewall: Principle of least privilege — deny by default, explicit allow only
