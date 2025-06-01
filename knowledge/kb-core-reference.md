# KB: Core Security Reference — Severity, CVSS, CWE, Remediation
# ALWAYS LOADED: This file applies to every assessment type

## CVSS v3.1 Severity Bands & Remediation SLAs
| Severity | Score Range | Remediation SLA | Business Definition |
|---|---|---|---|
| Critical | 9.0–10.0 | 24–48 hours | Unauthenticated, remote exploit. Trivial to exploit. Full system/data compromise. Immediate action required. |
| High | 7.0–8.9 | 7 days | Significant breach risk. Authenticated or moderate complexity. Likely exploited in the wild. |
| Medium | 4.0–6.9 | 30 days | Requires conditions, chaining, or user interaction. Moderate business impact. |
| Low | 0.1–3.9 | 90 days | Minimal standalone impact. Contributes to defence-in-depth weakness. |
| Informational | 0.0 | Best effort | No direct exploit path. Security hardening opportunity. |

## CVSS v3.1 Vector String Reference
```
AV: Network(N) Adjacent(A) Local(L) Physical(P)
AC: Low(L) High(H)
PR: None(N) Low(L) High(H)
UI: None(N) Required(R)
S:  Unchanged(U) Changed(C)
C/I/A: None(N) Low(L) High(H)

Common vectors:
Unauthenticated RCE:     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
Auth RCE:                AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8
IDOR/data exposure:      AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5
Stored XSS (session):    AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N = 8.2
Reflected XSS:           AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
CSRF state change:        AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N = 6.5
```

## Core CWE Reference — Universal
| Category | CWE | Name |
|---|---|---|
| Injection | CWE-89 | SQL Injection |
| Injection | CWE-78 | OS Command Injection |
| Injection | CWE-79 | Cross-site Scripting |
| Injection | CWE-94 | Code Injection |
| Injection | CWE-611 | XML External Entity (XXE) |
| Injection | CWE-918 | Server-Side Request Forgery |
| Auth | CWE-287 | Improper Authentication |
| Auth | CWE-307 | Improper Restriction of Excessive Auth Attempts |
| Auth | CWE-384 | Session Fixation |
| Auth | CWE-521 | Weak Password Requirements |
| Auth | CWE-798 | Hard-coded Credentials |
| Auth | CWE-330 | Use of Insufficiently Random Values |
| Access Control | CWE-200 | Exposure of Sensitive Information |
| Access Control | CWE-284 | Improper Access Control |
| Access Control | CWE-285 | Improper Authorisation |
| Access Control | CWE-352 | Cross-Site Request Forgery |
| Access Control | CWE-639 | IDOR / Authorisation Bypass via User-Controlled Key |
| Access Control | CWE-862 | Missing Authorisation |
| Crypto | CWE-311 | Missing Encryption of Sensitive Data |
| Crypto | CWE-319 | Cleartext Transmission |
| Crypto | CWE-326 | Inadequate Encryption Strength |
| Crypto | CWE-327 | Use of Broken Algorithm |
| Crypto | CWE-916 | Insufficient Password Hashing Iterations |
| Input Validation | CWE-20 | Improper Input Validation |
| Input Validation | CWE-22 | Path Traversal |
| Input Validation | CWE-434 | Unrestricted File Upload |
| Input Validation | CWE-601 | Open Redirect |
| Config | CWE-16 | Configuration |
| Config | CWE-209 | Sensitive Info in Error Messages |
| Config | CWE-548 | Directory Listing |
| Config | CWE-693 | Protection Mechanism Failure |
| Privilege | CWE-250 | Execution with Unnecessary Privileges |
| Privilege | CWE-269 | Improper Privilege Management |
| Privilege | CWE-522 | Insufficiently Protected Credentials |

## Regulatory Mapping — Universal
| Regulation | Requirement | Applies To |
|---|---|---|
| GDPR Article 32 | Technical security measures appropriate to risk | Any org handling EU personal data |
| GDPR Article 33 | 72-hour breach notification | Any org handling EU personal data |
| PCI DSS v4.0 Req 6.2 | Bespoke software security | Cardholder data environments |
| PCI DSS v4.0 Req 11.3 | Penetration testing | Cardholder data environments |
| ISO 27001:2022 A.8.8 | Management of technical vulnerabilities | ISO 27001 certified/pursuing |
| NIS2 Article 21 | Cybersecurity risk management measures | Essential/important entities (EU) |
| FCA SYSC | Operational resilience, cyber risk | UK Financial Services |
| SOC 2 CC6 | Logical and physical access controls | SaaS / service organisations |
| HIPAA Security Rule | Technical safeguards | US healthcare / business associates |

## Universal Remediation Boilerplate

### Defence in Depth (apply to all assessments)
- Deploy WAF with custom rules targeting confirmed vulnerability classes
- Implement comprehensive application security logging (SIEM integration)
- Establish vulnerability management programme with defined SLAs
- Integrate SAST/DAST tooling into CI/CD pipeline
- Conduct developer security training (OWASP / SANS)
- Schedule annual penetration test and quarterly vulnerability scanning
- Implement responsible disclosure / bug bounty programme

### Credential Security (universal)
- Enforce MFA on all privileged accounts and externally-facing systems
- Implement password manager and complexity policy (16+ chars minimum)
- Rotate all secrets/credentials confirmed exposed immediately
- Audit service account permissions — apply principle of least privilege
- Deploy privileged access management (PAM) for admin accounts
