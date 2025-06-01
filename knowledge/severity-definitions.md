# Severity Definitions

## Critical — CVSS 9.0–10.0
Immediate, direct risk of full system or data compromise. No user interaction required.
Examples: Unauthenticated RCE, SQLi with DBA-level access, hardcoded credentials to critical systems.
Remediation SLA: 24–48 hours

## High — CVSS 7.0–8.9
Significant risk of data breach, privilege escalation, or service disruption.
Examples: Authenticated RCE, SSRF with internal access, broken access control on sensitive data.
Remediation SLA: 7 days

## Medium — CVSS 4.0–6.9
Moderate risk, often requires chaining or additional conditions.
Examples: Stored XSS, IDOR with limited impact, missing security headers enabling attack vectors.
Remediation SLA: 30 days

## Low — CVSS 0.1–3.9
Minor risk, limited impact, or difficult to exploit.
Examples: Reflected XSS with minimal impact, verbose error messages, weak TLS config.
Remediation SLA: 90 days

## Informational — CVSS 0.0
No direct exploitable risk but represents a security concern or best practice gap.
Examples: Missing headers, outdated software with no known exploits, overly verbose responses.
Remediation SLA: Best effort / next patch cycle
