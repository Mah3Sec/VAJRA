# OWASP Top 10 (2021)

## A01 – Broken Access Control
IDOR, privilege escalation, missing function-level access control, CORS misconfiguration.
CWE: 200, 284, 285, 862, 863

## A02 – Cryptographic Failures
Weak encryption, cleartext transmission, weak password hashing (MD5/SHA1), hardcoded keys.
CWE: 261, 296, 310, 319, 321, 326, 327

## A03 – Injection
SQL injection, LDAP injection, OS command injection, SSTI, XXE.
CWE: 73, 89, 564, 917

## A04 – Insecure Design
Missing rate limiting, insufficient threat modeling, insecure design patterns.
CWE: 73, 183, 209, 352

## A05 – Security Misconfiguration
Default credentials, verbose errors, missing hardening, open cloud storage, unnecessary services.
CWE: 2, 11, 13, 15, 16

## A06 – Vulnerable and Outdated Components
Outdated libraries/frameworks, unpatched OS/software, unsupported components.
CWE: 1104

## A07 – Identification and Authentication Failures
Weak passwords, missing MFA, credential stuffing, session fixation, insecure session tokens.
CWE: 255, 259, 287, 288, 290, 294, 295, 330

## A08 – Software and Data Integrity Failures
Insecure deserialization, unsigned updates, malicious plugins, CSRF.
CWE: 345, 353, 426, 494, 502, 565, 784

## A09 – Security Logging and Monitoring Failures
No audit logs, missing alerts on attacks, insufficient log detail.
CWE: 117, 223, 532, 778

## A10 – Server-Side Request Forgery (SSRF)
SSRF to internal services, cloud metadata access, localhost bypass.
CWE: 918
