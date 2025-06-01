# KB: Web Application Security
# Applies to: Web app pentesting, OWASP WSTG, browser-based vulnerabilities

## OWASP Top 10 (2021) — Web Application
| ID | Category | Key CWEs | Common Findings |
|---|---|---|---|
| A01 | Broken Access Control | CWE-200,284,285,862,863 | IDOR, privilege escalation, missing authz, CORS misconfig |
| A02 | Cryptographic Failures | CWE-261,310,319,326,327 | Cleartext transmission, weak TLS, weak hashing (MD5/SHA1) |
| A03 | Injection | CWE-73,89,564,917 | SQLi, SSTI, XSS, XXE, LDAP injection |
| A04 | Insecure Design | CWE-73,183,209,352 | Missing rate limiting, insecure design patterns |
| A05 | Security Misconfiguration | CWE-2,11,13,15,16 | Default creds, verbose errors, missing headers, open dirs |
| A06 | Vulnerable Components | CWE-1104 | Outdated libs, unpatched frameworks |
| A07 | Auth Failures | CWE-255,259,287,330 | Weak passwords, no MFA, session fixation |
| A08 | Integrity Failures | CWE-345,494,502 | Insecure deserialization, unsigned updates |
| A09 | Logging Failures | CWE-117,223,532,778 | No audit logs, missing attack alerts |
| A10 | SSRF | CWE-918 | Internal service access, metadata endpoint abuse |

## Critical Web Vulnerabilities — CVSS & CWE Reference
| Vulnerability | CVSS Range | CWE | OWASP |
|---|---|---|---|
| SQL Injection (auth bypass) | 9.8 | CWE-89 | A03 |
| SQL Injection (data exfil) | 9.1 | CWE-89 | A03 |
| Remote Code Execution via file upload | 9.5 | CWE-434 | A04/A05 |
| Stored XSS | 8.2 | CWE-79 | A03 |
| Reflected XSS | 7.4 | CWE-79 | A03 |
| DOM-based XSS | 6.5 | CWE-79 | A03 |
| IDOR / Broken Access Control | 8.1 | CWE-639 | A01 |
| Missing Function-Level Access Control | 8.4 | CWE-285 | A01 |
| Session Fixation | 8.0 | CWE-384 | A07 |
| CSRF on sensitive action | 6.5 | CWE-352 | A01 |
| XXE Injection | 7.5 | CWE-611 | A03 |
| SSRF | 8.6 | CWE-918 | A10 |
| Open Redirect | 5.4 | CWE-601 | A01 |
| Clickjacking | 4.3 | CWE-1021 | A05 |
| Missing security headers | 5.3 | CWE-693 | A05 |
| Directory listing | 3.7 | CWE-548 | A05 |
| Insecure cookie (no HttpOnly/Secure) | 4.0 | CWE-614 | A07 |
| Hardcoded credentials in source | 9.1 | CWE-798 | A07 |
| Weak TLS config | 3.7 | CWE-326 | A02 |
| Path traversal | 7.5 | CWE-22 | A03 |

## HTTP Security Headers — Required Set
| Header | Required Value | Missing CVSS Impact |
|---|---|---|
| Content-Security-Policy | default-src 'self'; script-src 'self' | +1.5 XSS exploitability |
| X-Frame-Options | DENY or SAMEORIGIN | Clickjacking enabled |
| X-Content-Type-Options | nosniff | MIME sniffing enabled |
| Strict-Transport-Security | max-age=31536000; includeSubDomains | Downgrade attack risk |
| Referrer-Policy | strict-origin-when-cross-origin | Information leakage |
| Permissions-Policy | geolocation=(), microphone=() | Browser API abuse |

## Web Testing Methodology — OWASP WSTG v4.2 Phases
1. Information Gathering (WSTG-INFO): DNS, HTTP headers, JS source, tech fingerprint
2. Configuration Testing (WSTG-CONF): TLS, headers, server config, error handling
3. Identity Management (WSTG-IDNT): User enumeration, account policies
4. Authentication Testing (WSTG-ATHN): Brute force, default creds, MFA bypass
5. Authorisation Testing (WSTG-AUTHZ): IDOR, privilege escalation, CORS
6. Session Management (WSTG-SESS): Token entropy, fixation, hijacking
7. Input Validation (WSTG-INPV): SQLi, XSS, XXE, SSRF, path traversal
8. Error Handling (WSTG-ERRH): Stack traces, verbose errors
9. Cryptography (WSTG-CRYP): TLS config, weak ciphers
10. Business Logic (WSTG-BUSL): Workflow bypass, race conditions

## Remediation Deadlines (from report date)
Critical (9.0+): 24–48 hours | High (7.0–8.9): 7 days | Medium (4.0–6.9): 30 days | Low (0.1–3.9): 90 days
