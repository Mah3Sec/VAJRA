# KB: Phishing, Social Engineering & BEC Assessments
# Applies to: Phishing simulation, vishing, smishing, BEC, user awareness testing

## Phishing Campaign Metrics — Industry Benchmarks (2024)
| Metric | Global Avg | Financial Sector | Tech Sector | Healthcare |
|---|---|---|---|---|
| Click rate (untrained) | 32.4% | 28.1% | 18.2% | 34.7% |
| Click rate (trained 1yr) | 13.2% | 11.5% | 7.8% | 15.3% |
| Click rate (trained ongoing) | 4.6% | 3.9% | 2.1% | 5.8% |
| Cred submission rate (of clicks) | 55–65% | 50–60% | 45–55% | 60–70% |
| Report rate | 15–25% | 20–28% | 22–30% | 12–18% |
| Mean time to first click | 3–8 min | 4–9 min | 5–12 min | 2–5 min |
*Sources: Proofpoint State of the Phish 2024, KnowBe4 Phishing Industry Benchmarks 2024*

## Phishing Pretext Effectiveness (Typical Click Rate)
| Pretext Type | Avg Click Rate | Why It Works |
|---|---|---|
| IT: Password reset / account locked | 38% | Fear + urgency + authority |
| HR: Policy update, benefit change | 34% | Authority + relevance |
| Finance: Invoice, payment notification | 32% | Urgency + financial concern |
| Executive impersonation (BEC setup) | 25% | Authority |
| Package delivery notification | 22% | Relevance, low suspicion |
| Security alert (fake SSO/MFA prompt) | 42% | Fear + false legitimacy |
| LinkedIn connection / job opportunity | 18% | Curiosity |

## Email Security Controls Assessment
| Control | What It Prevents | Bypass Methods | Recommendation |
|---|---|---|---|
| SPF | Spoofing sender domain | Lookalike domain, subdomain spoof | Enforce hard fail (-all) |
| DKIM | Message tampering | Replay from legitimate source | 2048-bit key, rotate 6-monthly |
| DMARC | SPF/DKIM bypass | Lookalike domain (no DMARC bypass) | Enforce p=reject, monitor reports |
| Secure Email Gateway | Malware, known phishing | Zero-day, evasion, HTML smuggling | Tune rules, sandbox attachments |
| URL Rewriting / Safe Links | Malicious links | Click-time bypass, direct IP | Enable detonation sandbox |
| Anti-spoofing | Internal domain spoof | Compromised account | MFA + impossible travel alerts |
| Sandboxing | Malware attachments | Delayed execution, VM detection | Behaviour-based sandbox |

## AiTM (Adversary-in-The-Middle) Phishing — MFA Bypass
- Tools: Evilginx3, Modlishka, Muraena
- Method: Reverse proxy between victim and legitimate site
- Captures: Session cookies POST-MFA authentication (bypasses TOTP/SMS MFA)
- Does NOT bypass: FIDO2/WebAuthn hardware keys, passkeys (phishing-resistant MFA)
- Detection: Impossible travel, new device sign-in, session from unexpected IP
- Remediation: Migrate to FIDO2/passkeys; Conditional Access with device compliance

## BEC (Business Email Compromise) — Patterns & Impact
| BEC Type | Method | Average Loss | Key Indicator |
|---|---|---|---|
| CEO fraud / executive impersonation | Spoofed executive email to finance | $50K–$500K | Urgency, secrecy, wire transfer |
| Invoice fraud | Vendor impersonation, changed banking details | $10K–$200K | Changed bank account in email |
| Payroll diversion | HR/payroll impersonation, direct deposit change | $5K–$50K per employee | Urgency, W-2 requests |
| Attorney impersonation | Legal firm spoofing, acquisition pressure | $100K+ | Legal urgency, confidentiality |
| Account compromise BEC | Real compromised email account | Highest loss | Anomalous sending patterns |

## Vishing (Voice Phishing) Assessment
- Common pretexts: IT helpdesk, bank fraud team, government/HMRC/IRS, vendor support
- Information typically extracted: Credentials, MFA codes, employee info, system access
- Key indicator: Unusual urgency, requests for credentials over phone
- Remediation: Callback verification procedures, never provide credentials by phone

## Smishing (SMS Phishing) Assessment
- Common pretexts: Package delivery, bank alert, government message, prize notification
- Attack vector: Malicious link or callback number in SMS
- AiTM via SMS: OTP interception for account takeover
- Remediation: User awareness training, report-a-phish SMS shortcode

## Security Awareness Maturity Model
| Level | Description | Click Rate | Report Rate |
|---|---|---|---|
| 1 — Unknown | No measurement, no training | > 30% | < 5% |
| 2 — Compliance | Annual training only | 20–30% | 5–15% |
| 3 — Awareness | Regular training + simulation | 10–20% | 15–25% |
| 4 — Security Minded | Continuous training, low susceptibility | 5–10% | 25–40% |
| 5 — Security Embedded | Culture-level, near-zero susceptibility | < 5% | > 40% |

## Regulatory Mapping — Phishing / Social Engineering
- GDPR Article 32: Credential compromise = personal data breach → 72hr notification
- PCI DSS v4.0 Req 12.6: Security awareness training including phishing awareness
- ISO 27001:2022 A.6.3: Information security awareness, education and training
- NIS2 Directive Art 21: Measures addressing social engineering
- FCA SYSC 13: Operational resilience including social engineering risk
