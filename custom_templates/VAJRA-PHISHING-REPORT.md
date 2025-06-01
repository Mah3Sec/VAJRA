# VAJRA PHISHING CAMPAIGN ASSESSMENT REPORT TEMPLATE
# Framework: NIST SP 800-177 / SANS Security Awareness / Email Security Best Practices
# Version: 3.0 — Updated March 2026

---

# Executive Summary

{{client}} commissioned {{tester}} to conduct a phishing simulation campaign against [TARGET AUDIENCE DESCRIPTION] during the period ending {{date}}. The campaign assessed the organisation's susceptibility to social engineering attacks and evaluated the effectiveness of existing security awareness training and email security controls.

Engagement Reference: {{engagement_ref}} | Classification: {{classification}}

## Campaign Summary

| Metric | Value |
|---|---|
| Engagement Reference | {{engagement_ref}} |
| Total Recipients Targeted | [Number] |
| Emails Successfully Delivered | [Number] ([X%]) |
| Emails Opened | [Number] ([X%]) |
| Links Clicked / Attachments Opened | [Number] ([X%] click rate) |
| Credentials Harvested / Forms Submitted | [Number] ([X%] of clickers) |
| MFA Bypass Attempted (AiTM) | [Yes / No] |
| MFA Tokens Captured | [Number — if AiTM used] |
| Staff Who Reported the Email | [Number] ([X%] report rate) |
| Campaign Duration | [X days] |
| Industry Benchmark Click Rate | [X% — source: Proofpoint/Verizon DBIR 2024] |
| {{client}} vs Benchmark | [Above / Below / At industry average] |
| Report Version | {{report_version}} |
| Classification | {{classification}} |

## Strategic Assessment

[3–5 sentences for the board: what the campaign tested, the headline susceptibility rate, comparison to industry benchmarks, and the most important improvement required. Use plain language.]

The most critical recommendation for {{client}} is: **[TOP RECOMMENDATION — e.g. deploy phishing-resistant MFA / mandatory awareness training / DMARC enforcement]**

---

# 1. Engagement Overview

## 1.1 Campaign Configuration

| Field | Details |
|---|---|
| Client | {{client}} |
| Lead Assessor | {{tester}} |
| Assessment Team | {{assessment_team}} |
| Target Audience | [All staff / Finance dept / IT / C-suite / [X] departments] |
| Total Recipients | [Number] |
| Campaign Type | [Credential Harvest / Attachment / QR Code / Vishing / Multi-Stage] |
| Phishing Pretext | [Describe the lure — e.g. "IT Security Alert: Password expiry", "HR: Updated Benefits"] |
| Spoofed As | [Entity impersonated — e.g. IT Helpdesk / Microsoft / HMRC / CEO] |
| Phishing Domain Used | [e.g. company-itsupport[.]com — registered for this engagement] |
| AiTM Proxy Used | [Yes — Evilginx2 / Modlishka / No] |
| MFA Bypass Attempted | [Yes / No] |
| Blue Team Awareness | [Blind / SOC Lead Only / Full Awareness] |
| Scope | {{scope}} |
| Date | {{date}} |
| Classification | {{classification}} |

## 1.2 Email Security Controls Assessed

| Control | Configured | Result |
|---|---|---|
| SPF (Sender Policy Framework) | [Yes / No / Partial] | [Pass / Fail / Soft Fail] |
| DKIM (DomainKeys Identified Mail) | [Yes / No] | [Pass / Fail] |
| DMARC (Policy Enforcement) | [None / Quarantine / Reject] | [Enforced / Not Enforced] |
| BIMI (Brand Indicators) | [Yes / No] | [Present / Absent] |
| Email Gateway Filtering | [Product name] | [Blocked X% / Delivered all] |
| Anti-Spoofing Headers | [Yes / No] | [Checked / Not Checked] |
| Safe Links / URL Rewriting | [Yes / No — Microsoft Defender / Proofpoint] | [Active / Inactive] |
| Sandboxing | [Yes / No — Attachment scanning] | [Active / Inactive] |
| Phishing-Resistant MFA | [FIDO2 / Hardware Token / None] | [Deployed / Not Deployed] |

## 1.3 Methodology

The campaign followed a structured kill chain aligned with real-world phishing operations:

| Phase | Activity | Standard |
|---|---|---|
| Reconnaissance | LinkedIn/OSINT for employee names, email format, org structure | PTES Intelligence Gathering |
| Infrastructure Setup | Domain registration, SSL cert, phishing page deployment | OpSec best practice |
| Email Delivery | Targeted spear-phishing with personalised pretext | NIST SP 800-177 |
| Credential Capture | Real-time credential logging via [GoPhish / Evilginx2 / Custom] | — |
| AiTM (if applicable) | Session token capture bypassing MFA via reverse proxy | — |
| Awareness Measurement | Click, submit, and report rates tracked per department | SANS KnowBe4 methodology |
| Feedback Loop | Immediate notification and training redirect on click | — |

---

# 2. Campaign Results

## 2.1 Overall Susceptibility Metrics

| Metric | Count | Rate | Industry Benchmark |
|---|---|---|---|
| Emails Sent | [N] | 100% | — |
| Delivered (not blocked) | [N] | [X%] | — |
| Opened | [N] | [X%] | ~35% (Proofpoint 2024) |
| Clicked Link / Opened Attachment | [N] | [X%] | ~17% (Verizon DBIR 2024) |
| Credentials Submitted | [N] | [X%] | ~5–10% (industry avg) |
| Reported to Security Team | [N] | [X%] | ~20% (mature orgs) |
| Clicked AND Reported | [N] | [X%] | — |

**Susceptibility Score:** [HIGH / MEDIUM / LOW — based on click + submit rate vs industry benchmark]

## 2.2 Departmental Susceptibility Breakdown

| Department | Recipients | Clicked | Submit Rate | Reported | Risk Level |
|---|---|---|---|---|---|
| Finance | [N] | [N] ([X%]) | [X%] | [N] | [HIGH/MED/LOW] |
| IT / Engineering | [N] | [N] ([X%]) | [X%] | [N] | [HIGH/MED/LOW] |
| HR | [N] | [N] ([X%]) | [X%] | [N] | [HIGH/MED/LOW] |
| Executive / C-Suite | [N] | [N] ([X%]) | [X%] | [N] | [HIGH/MED/LOW] |
| Operations | [N] | [N] ([X%]) | [X%] | [N] | [HIGH/MED/LOW] |
| Sales / Marketing | [N] | [N] ([X%]) | [X%] | [N] | [HIGH/MED/LOW] |

## 2.3 Susceptibility by Seniority

| Level | Recipients | Click Rate | Submit Rate | Observation |
|---|---|---|---|---|
| C-Suite / Director | [N] | [X%] | [X%] | [Note — executives often targeted by BEC] |
| Manager | [N] | [X%] | [X%] | — |
| Senior Staff | [N] | [X%] | [X%] | — |
| Junior / Graduate | [N] | [X%] | [X%] | — |
| Contractor / Third Party | [N] | [X%] | [X%] | — |

## 2.4 Time-to-Click Analysis

| Time Window | Clicks |
|---|---|
| Within 1 hour of delivery | [N] ([X%]) |
| 1–24 hours | [N] ([X%]) |
| 24–72 hours | [N] ([X%]) |
| After 72 hours | [N] ([X%]) |

> **Note:** [X%] of all clicks occurred within the first [Y] hours, indicating [observation about urgency-based susceptibility].

---

# 3. Technical Findings

[AI: For each technical finding/observation, use the format below. P-NNN format for phishing findings.]

### P-001 — [Finding Title] | [Severity] | CVSS: [Score]

**Severity:** [Critical / High / Medium / Low]
**CVSS v3.1 Score:** [Score]
**CVSS Vector:** [Vector string]
**CWE:** [CWE-1021 — Improper Restriction of Rendered UI Layers / CWE-290 — Auth Bypass / etc.]
**Affected Control:** [Email gateway / MFA / Awareness training / DMARC]
**Detection Status:** [Detected / Not Detected by Blue Team]
**Root Cause:** [Technical root cause — e.g. DMARC not in reject mode / No phishing-resistant MFA]
**Retest Status:** Pending Retest

#### Description

[Technical description of what control failed or what susceptibility was found. Include specifics — what header was missing, what policy was misconfigured, what training gap existed.]

#### Evidence

> 📸 Screenshot/PoC: Insert evidence — phishing page screenshot, email header analysis, credential capture confirmation, AiTM session token capture

```
[Email headers showing SPF/DKIM/DMARC results or technical output confirming the finding]
```

#### Business Impact

- **[Impact 1]:** [Credential compromise consequence — account takeover, data breach]
- **[Impact 2]:** [MFA bypass consequence if AiTM used]
- **[Impact 3]:** [Regulatory consequence — GDPR Art. 32, PCI DSS Req 12.6]
- **[Impact 4]:** [Reputational/financial consequence — BEC, ransomware deployment risk]

#### Remediation

- **Immediate:** [Specific fix — enforce DMARC reject, deploy phishing-resistant MFA, block domain]
- **Short-Term (30 days):** [Targeted training for high-risk departments, mandatory simulation re-run]
- **Long-Term:** [Phishing-resistant MFA programme, BIMI implementation, Zero Trust email policy]
- **Training Recommendation:** [Specific awareness training module — e.g. KnowBe4 credential harvest module]
- **Reference:** [CISA Phishing Guidance / Microsoft Defender configuration guide / Google Workspace DMARC setup]

[Repeat P-002, P-003, etc.]

---

# 4. Awareness Programme Assessment

## 4.1 Current Training Effectiveness

| Training Programme | Deployed | Frequency | Last Completion Rate | Assessment |
|---|---|---|---|---|
| Phishing simulation baseline | [Yes/No] | [Quarterly/Annual] | [X%] | [Adequate/Insufficient] |
| Security awareness training | [Product name] | [Frequency] | [X%] | [Adequate/Insufficient] |
| Mandatory onboarding security | [Yes/No] | [Once/Annual] | [X%] | [Adequate/Insufficient] |
| Incident reporting procedures | [Yes/No] | — | — | [Clear/Unclear] |

## 4.2 Reporting Culture Assessment

**Report Rate:** [X%] of recipients who clicked the phishing link also reported it to the security team.

[Assessment of the organisation's security culture — whether staff feel empowered to report suspicious emails without fear of blame.]

---

# 5. Remediation Roadmap

Prioritised recommendations with time-bound deadlines calculated from {{date}}.

[AI: Insert table with Priority | ID | Recommendation | Severity | SLA | Owner | Estimated Effort | Status]

---

# 6. Appendix

## A. Phishing Email Analysis

**Subject Line Used:** [Full subject line]
**Sender (Spoofed):** [display name <spoofed@domain.com>]
**Return Path:** [actual@phishingdomain.com]
**Lure Description:** [Describe the social engineering pretext in detail]
**Call to Action:** [What the email asked the recipient to do]
**Landing Page:** [Description of credential harvest page or attachment behaviour]

**Email Header Analysis:**

| Header | Value | Assessment |
|---|---|---|
| SPF | [Pass/Fail/SoftFail] | [Explanation] |
| DKIM | [Pass/Fail/None] | [Explanation] |
| DMARC | [Pass/Fail/None/Policy=none] | [Explanation] |
| X-Spam-Score | [Score] | [Above/Below threshold] |
| Delivered-To | [Inbox / Spam / Quarantine] | [Assessment] |

## B. AiTM / MFA Bypass Details (if applicable)

**Technique Used:** [Evilginx2 phishlet / Modlishka / Custom reverse proxy]
**Credential Format Captured:** [Username + Password + Session Cookie]
**MFA Type Bypassed:** [TOTP / Push notification / SMS OTP]
**Session Token Validity:** [X hours — duration of captured session]
**Detection by Blue Team:** [Yes / No — what was/wasn't detected]

**Why this matters:** AiTM attacks bypass traditional MFA entirely. Only phishing-resistant MFA (FIDO2 hardware keys, passkeys, certificate-based auth) prevents this attack class. TOTP, SMS, and push notification MFA are all vulnerable.

## C. Industry Benchmarks (2024)

| Benchmark | Source | Value |
|---|---|---|
| Average click rate (untrained staff) | Proofpoint State of Phish 2024 | 17% |
| Average click rate (trained staff) | KnowBe4 Phishing Industry Benchmark 2024 | 4–8% |
| Average credential submission rate | Verizon DBIR 2024 | 2–5% |
| Average report rate (mature orgs) | SANS Security Awareness Report 2024 | 20–30% |
| % of breaches involving phishing | Verizon DBIR 2024 | 36% |
| % of BEC attacks using AiTM | Microsoft Digital Defense Report 2024 | 35%+ |

## D. Regulatory Mapping

| Requirement | Standard | Finding ID | Status |
|---|---|---|---|
| Security awareness training | PCI DSS v4.0 Req 12.6 | P-XXX | [Pass/Fail] |
| Phishing-resistant MFA | NIST SP 800-63B AAL3 | P-XXX | [Pass/Fail] |
| Email authentication | NCSC Email Security | P-XXX | [Pass/Fail] |
| Incident reporting capability | ISO 27001:2022 A.6.8 | P-XXX | [Pass/Fail] |
| Personal data breach risk | GDPR Article 32 | P-XXX | [At Risk] |

