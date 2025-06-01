# Remediation Boilerplate

## SQL Injection
Use parameterized queries or prepared statements. Never concatenate user input into SQL.
Apply least privilege to DB accounts. Consider WAF as defense-in-depth.

## XSS
Context-aware output encoding (HTML, JS, CSS, URL). Implement strict Content Security Policy.
Use frameworks that auto-escape. Validate and sanitize server-side.

## Broken Access Control / IDOR
Server-side authorization check on every request. Use indirect object references (GUIDs).
Log all access control failures. Apply principle of least privilege.

## Hardcoded Credentials
Remove immediately. Rotate all exposed secrets.
Use environment variables or secrets manager (Vault, AWS Secrets Manager).
Add pre-commit hooks to scan for secrets.

## SSRF
Validate and allowlist permitted destination URLs.
Block requests to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16).
Disable HTTP redirects or validate redirected URLs.

## Missing Security Headers
Implement: Content-Security-Policy, X-Content-Type-Options: nosniff,
X-Frame-Options: DENY, Strict-Transport-Security, Referrer-Policy, Permissions-Policy.

## Weak TLS
Disable TLS 1.0/1.1. Enforce TLS 1.2 minimum, prefer TLS 1.3.
Disable weak ciphers (RC4, DES, 3DES, EXPORT). Implement HSTS.

## Missing MFA
Implement MFA for all privileged accounts and internet-facing apps.
Prefer authenticator apps (TOTP) or hardware tokens over SMS.

## Outdated Components
Establish software inventory and vulnerability management process.
Subscribe to security advisories. Automate dependency scanning in CI/CD.
