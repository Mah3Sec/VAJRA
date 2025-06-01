# KB: Active Directory & Internal Infrastructure Testing
# Applies to: AD pentesting, internal network, domain enumeration, privilege escalation

## Active Directory Attack Chain (Typical Path)
1. Initial foothold (phishing/VPN/exposed service)
2. Local enumeration (whoami, net user, ipconfig, routes)
3. Domain enumeration (BloodHound, PowerView, ldapsearch)
4. Credential access (Responder, LLMNR poisoning, AS-REP roasting, Kerberoasting)
5. Lateral movement (PtH, PtT, WMI, PSExec, RDP, SMB)
6. Privilege escalation (token impersonation, GPP creds, ACL abuse, DCSync)
7. Domain dominance (Golden Ticket, Silver Ticket, Skeleton Key, DCShadow)

## Active Directory Findings — CVSS & CWE
| Finding | CVSS | CWE | Impact |
|---|---|---|---|
| DCSync attack (Domain Admin achieved) | 10.0 | CWE-522 | Full domain compromise, all hashes dumped |
| Kerberoastable service accounts with weak passwords | 8.8 | CWE-521 | Service account escalation to domain admin |
| AS-REP Roasting (no pre-auth required) | 8.8 | CWE-522 | Offline hash cracking of user accounts |
| LLMNR/NBT-NS poisoning (Responder) | 8.8 | CWE-290 | Credential interception on internal network |
| SMB signing disabled domain-wide | 8.8 | CWE-294 | NTLM relay to domain controller |
| Pass-the-Hash successful | 8.8 | CWE-522 | Lateral movement without password |
| GPP credentials in SYSVOL | 9.8 | CWE-256 | Cleartext domain credentials in group policy |
| Unconstrained Kerberos delegation | 8.8 | CWE-284 | TGT capture → impersonation of any user |
| Constrained delegation abuse | 7.5 | CWE-284 | Service account impersonation |
| AdminSDHolder ACL abuse | 8.8 | CWE-284 | Persistent privileged access |
| WriteDACL / GenericAll on Domain Admins | 9.0 | CWE-284 | Immediate DA escalation |
| Domain trust exploitation | 8.8 | CWE-284 | Cross-domain / cross-forest privilege escalation |
| Print Spooler abuse (PrintNightmare) | 8.8 | CWE-269 | Unauthenticated SYSTEM-level code execution |
| noPac / CVE-2021-42278+42287 | 9.8 | CWE-284 | Domain admin from standard user in seconds |
| Zerologon / CVE-2020-1472 | 10.0 | CWE-330 | Unauthenticated domain controller takeover |

## BloodHound Attack Path Queries (Key Findings to Report)
- Shortest path to Domain Admins from owned computers
- Kerberoastable users with path to high-value targets
- Users with DCSync rights (GetChanges + GetChangesAll)
- Computers with unconstrained delegation
- ACL paths: WriteDACL, GenericAll, GenericWrite, ForceChangePassword
- Cross-domain trust attack paths

## Enumeration Commands Reference
```
# Domain info
net user /domain | Get-ADUser -Filter * | whoami /all
# Kerberoasting
GetUserSPNs.py domain/user:pass -dc-ip DC_IP -request
# AS-REP Roasting  
GetNPUsers.py domain/ -usersfile users.txt -no-pass -dc-ip DC_IP
# BloodHound collection
SharpHound.exe -c All --zipfilename loot.zip
# DCSync (requires replication rights)
secretsdump.py domain/admin:pass@DC_IP
```

## Remediation Guidance
- Kerberoasting: Enforce 25+ char random passwords for service accounts; use gMSA
- AS-REP Roasting: Enable Kerberos pre-authentication for all accounts
- LLMNR/NBT-NS: Disable via GPO (Network → DNS Client → Turn off multicast)
- SMB signing: Require signing on all domain members via GPO
- GPP credentials: Run Get-GPPPassword; remove cPassword from SYSVOL; apply MS14-025
- Unconstrained delegation: Migrate to constrained or resource-based constrained delegation
- Tiering model: Implement admin tier model (T0=DC, T1=server, T2=workstation)
- LAPS: Deploy Microsoft LAPS to randomise local admin passwords
