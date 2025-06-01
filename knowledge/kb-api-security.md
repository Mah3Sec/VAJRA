# KB: API Security Testing
# Applies to: REST API, GraphQL, SOAP, gRPC, mobile backend APIs

## OWASP API Security Top 10 (2023)
| ID | Category | CWE | Key Test Cases |
|---|---|---|---|
| API1 | Broken Object Level Authorization | CWE-639 | Change object IDs in requests, access other users' data |
| API2 | Broken Authentication | CWE-287,798 | Weak JWT, token replay, missing expiry, default creds |
| API3 | Broken Object Property Level Auth | CWE-213,915 | Mass assignment, over-posting hidden fields |
| API4 | Unrestricted Resource Consumption | CWE-770 | No rate limiting, no pagination limits, large payload abuse |
| API5 | Broken Function Level Authorization | CWE-285 | Access admin endpoints with user token, verb tampering |
| API6 | Unrestricted Access to Sensitive BizFlows | CWE-841 | Workflow bypass, order manipulation, coupon abuse |
| API7 | Server-Side Request Forgery | CWE-918 | Webhook URL manipulation, import URL abuse |
| API8 | Security Misconfiguration | CWE-16,209 | Debug endpoints, verbose errors, CORS *, unused HTTP verbs |
| API9 | Improper Inventory Management | CWE-1059 | Shadow APIs, deprecated versions, undocumented endpoints |
| API10 | Unsafe Consumption of APIs | CWE-116 | Third-party API injection, unvalidated external data |

## JWT (JSON Web Token) Attack Surface
| Attack | Description | Test Method |
|---|---|---|
| Algorithm None | Set alg:none to bypass signature | Modify header, remove signature |
| RS256 → HS256 confusion | Use RSA public key as HMAC secret | Change alg, sign with public key |
| Weak secret brute-force | Short or guessable HMAC secret | hashcat/jwt-cracker against token |
| JWT without expiry | Token valid indefinitely | Check exp claim absence |
| kid header injection | SQLi/path traversal via kid param | Inject payloads in kid field |
| jwks_uri manipulation | Point to attacker-controlled JWKS | Replace jwks_uri in iss claim |

## REST API Common Findings
| Finding | CVSS | CWE | Test |
|---|---|---|---|
| BOLA/IDOR on resource endpoints | 8.1 | CWE-639 | Enumerate integer/UUID IDs |
| Missing authentication on sensitive endpoints | 9.1 | CWE-306 | Remove auth header, try unauthenticated |
| Mass assignment / parameter pollution | 7.5 | CWE-915 | POST extra fields (isAdmin, role, price) |
| No rate limiting on auth endpoints | 7.5 | CWE-307 | Brute-force credentials without lockout |
| Verbose error messages leaking stack traces | 5.3 | CWE-209 | Trigger errors with malformed input |
| CORS misconfiguration (wildcard) | 6.5 | CWE-942 | Check Access-Control-Allow-Origin: * |
| HTTP verb tampering | 6.5 | CWE-650 | Try PUT/DELETE on read-only resources |
| API versioning exposure | 3.7 | CWE-1059 | Try /v1/, /v2/, /beta/, /internal/ |
| Insecure direct reference in file download | 7.5 | CWE-22 | ../../../etc/passwd in filename param |

## GraphQL-Specific Testing
- Introspection enabled: `{"query": "{__schema{types{name}}}"}`
- Batching attacks for rate limit bypass: array of operations in single request
- Field suggestions leaking schema: intentional typos reveal valid field names
- Deeply nested queries for DoS: recursive depth without query complexity limits
- Missing object-level authorization: access other users' nodes by ID
- Mutation abuse: unauthenticated mutations, admin mutations accessible to users

## API Authentication Testing Checklist
- [ ] JWT signature validation (alg:none, key confusion)
- [ ] Token expiry enforced server-side
- [ ] Refresh token rotation and revocation
- [ ] API key entropy and rotation policy
- [ ] OAuth2 state parameter CSRF protection
- [ ] OAuth2 redirect_uri validation
- [ ] PKCE enforcement for public clients
- [ ] Scope enforcement (horizontal privilege escalation via scope manipulation)

## CVSS Scoring Notes for APIs
- BOLA with PII exposure: CVSS 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- Unauthenticated admin endpoint: CVSS 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- Mass assignment (privilege escalation): CVSS 8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)
