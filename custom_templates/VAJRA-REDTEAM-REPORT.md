# VAJRA RED TEAM ENGAGEMENT REPORT TEMPLATE
# Framework: MITRE ATT&CK v14 / TIBER-EU 2024 / CBEST / NIST SP 800-115 / PTES
# Version: 3.0 — Updated March 2026

---

# Executive Summary

{{client}} commissioned {{tester}} to conduct a full-scope adversarial simulation of {{target_system}} between [START DATE] and {{date}}. The engagement emulated a [THREAT ACTOR TYPE — e.g. financially motivated eCrime group / nation-state APT] and assessed the capability of {{client}}'s people, processes, and technology to detect, contain, and respond to a sophisticated targeted intrusion.

Engagement Reference: {{engagement_ref}} | Classification: {{classification}}

## Engagement Metrics

| Metric | Value |
|---|---|
| Engagement Reference | {{engagement_ref}} |
| Attack Scenarios Executed | [Number] |
| Objectives Achieved | [X of Y] |
| Crown Jewels Reached | [Yes / No / Partial] |
| Blue Team Detection Rate | [X%] |
| Mean Time to Initial Access (MTTIA) | [HH:MM] |
| Mean Time to Detect (MTTD) | [HH:MM average across detected events] |
| Mean Time to Respond (MTTR) | [HH:MM average] |
| Lateral Movement Steps | [Number of hops] |
| Persistence Mechanisms Deployed | [Number] |
| Report Version | {{report_version}} |
| Classification | {{classification}} |

## Strategic Assessment

[3–5 sentences for the board: what threat was simulated, what was achieved, what the overall resilience posture is, and the single most critical recommendation. Use plain language — no technical jargon.]

The single most important defensive recommendation for {{client}} is: **[TOP RECOMMENDATION]**

---

# 1. Engagement Overview

## 1.1 Objectives and Crown Jewels

**Primary Objective:** [Simulate threat actor X targeting Y — describe what "success" looks like for the attacker]

**Crown Jewels Defined:**

- [Crown Jewel 1 — system/data/asset and location]
- [Crown Jewel 2]
- [Crown Jewel 3]

**Threat Scenario Simulated:** [Threat actor profile — motivation, sophistication, known TTPs, MITRE ATT&CK group reference e.g. APT29, FIN7, SCATTERED SPIDER]

**Success Criteria:**

- [Criterion 1 — e.g. Domain Administrator access on DC01]
- [Criterion 2 — e.g. Read access to HR database]
- [Criterion 3 — e.g. Simulate data exfiltration of >100MB]

## 1.2 Scope and Rules of Engagement

| Field | Details |
|---|---|
| Client | {{client}} |
| Lead Assessor | {{tester}} |
| Assessment Team | {{assessment_team}} |
| In-Scope Systems | [Systems, networks, locations] |
| Out-of-Scope | [Production trading infra, external customer-facing services, etc.] |
| Engagement Type | [Full-Scope / Assumed Breach / Purple Team] |
| Tested From | {{tested_from}} |
| Engagement Period | [START DATE] to {{date}} |
| Blue Team Awareness | [Blind / SOC Lead Only / Full Awareness (Purple)] |
| C2 Framework | [Cobalt Strike / Havoc / Brute Ratel / Custom] |
| Initial Access Vector | [Spear phishing / External exploit / Physical / Insider] |
| Classification | {{classification}} |

## 1.3 Kill Chain Methodology (MITRE ATT&CK v14)

| Phase | MITRE Tactic | Techniques Used |
|---|---|---|
| Reconnaissance | TA0043 — Reconnaissance | T1595, T1589, T1590, T1591 |
| Resource Development | TA0042 — Resource Development | T1583, T1587, T1588 |
| Initial Access | TA0001 — Initial Access | [T1566.001 — Spear Phishing / T1190 — Exploit Public App] |
| Execution | TA0002 — Execution | [T1059.001 — PowerShell / T1059.003 — cmd] |
| Persistence | TA0003 — Persistence | [T1053.005 — Scheduled Task / T1136 — Create Account] |
| Privilege Escalation | TA0004 — Privilege Escalation | [T1574 — Hijack Execution Flow / T1068 — Exploit Vuln] |
| Defense Evasion | TA0005 — Defense Evasion | [T1070.004 — Indicator Removal / T1562.001 — Impair Defenses] |
| Credential Access | TA0006 — Credential Access | [T1003.001 — LSASS Dump / T1110 — Brute Force] |
| Discovery | TA0007 — Discovery | [T1082 — System Info / T1016 — Network Config / T1087 — Account] |
| Lateral Movement | TA0008 — Lateral Movement | [T1021.002 — SMB / T1550.002 — Pass-the-Hash] |
| Collection | TA0009 — Collection | [T1005 — Local Data / T1039 — Network Shares] |
| C2 | TA0011 — Command and Control | [T1071.001 — HTTPS / T1573 — Encrypted Channel] |
| Exfiltration | TA0010 — Exfiltration | [T1041 — Exfil over C2 / T1048 — Protocol] |
| Impact | TA0040 — Impact | [T1486 — Data Encrypted / T1531 — Account Access Removal] |

---

# 2. Attack Narrative

The following narrative provides a chronological account of the red team's activities across the engagement window.

## 2.1 Reconnaissance

[Describe OSINT, passive reconnaissance, and active scanning performed prior to the simulated attack. Include: domains discovered, employee data collected via LinkedIn/OSINT, email format, technology stack identified, and any credentials found in breach data.]

OSINT Sources Used: [Shodan / Censys / LinkedIn / GitHub / HaveIBeenPwned / theHarvester / Maltego]

## 2.2 Initial Access

[Describe the initial access technique in detail — include timestamp, which user/system was compromised, what payload was used, what C2 beacon was established. Include exact timestamps in UTC.]

**Timestamp:** [YYYY-MM-DD HH:MM:SS UTC]
**Technique:** [T1566.001 — Spearphishing Link]
**Target:** [user@domain.com — job title, department]
**Result:** [Cobalt Strike beacon established on WORKSTATION-NAME (IP)]

## 2.3 Establishing Persistence

[Describe persistence mechanisms deployed — scheduled tasks, registry keys, new accounts, WMI subscriptions. Include exact commands/artefacts left.]

```
[Command used to establish persistence — e.g. schtasks /create /sc ONLOGON /tn SystemUpdateMonitor /tr "C:\Windows\Temp\payload.exe"]
```

**Detection Status:** [Detected / Not Detected] — Blue team alert at [HH:MM:SS UTC] or "No alert generated"

## 2.4 Privilege Escalation

[Describe how privileges were escalated — which vulnerability, which account, timestamps.]

**Timestamp:** [YYYY-MM-DD HH:MM:SS UTC]
**Technique:** [T1574 — Misconfigured Service / T1068 — Kernel Exploit]
**Starting Context:** [domain\username — standard user]
**Achieved Context:** [domain\Administrator / NT AUTHORITY\SYSTEM]
**Detection Latency:** [X minutes — SIEM alert generated / No detection]

## 2.5 Lateral Movement and Objective Achievement

[Describe each lateral movement step with timestamps, techniques, and systems pivoted through. Use Stage 1 → Stage 2 → Stage 3 format.]

**Stage 1 — [Source] to [Target] ([Timestamp UTC]):** [Technique used — e.g. Pass-the-Hash via SMB. Tool: Impacket wmiexec.py. Credential: it_support NTLM hash]

**Stage 2 — [Source] to [Target] ([Timestamp UTC]):** [Technique and result]

**Stage 3 — [Source] to [Target] ([Timestamp UTC]):** [Technique and result — crown jewel reached]

**Data Exfiltration Simulation ([Timestamp UTC]):** [X files / Y MB via HTTPS to attacker-controlled server. No real data left the network — all simulated via pre-agreed dummy files.]

---

# 3. Observations and Technical Findings

[AI: For EACH observation/finding, use this format. Red team reports use O-NNN (Observation) format.
ALL sections — Description, Evidence, Impact, Remediation — are mandatory. Never leave empty.]

### O-001 — [Observation Title] | [Severity] | CVSS: [Score]

**Severity:** [Critical / High / Medium / Low / Informational]
**CVSS v3.1 Score:** [Score]
**CVSS Vector:** [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]
**MITRE Tactic:** [TA00XX — Tactic Name]
**MITRE Technique:** [TXXXX.XXX — Technique Name]
**CWE:** [CWE-XXX — Name]
**Affected System:** [HOSTNAME (IP) — role/description]
**Detection Status:** [Detected / Not Detected]
**Blue Team Response:** [Description or "No Response"]
**Root Cause:** [Technical root cause]
**Retest Status:** Pending Retest

#### Description

[Technical description of the observation — what weakness was found, how it was discovered, what the red team was able to do as a result.]

#### Evidence

[Describe artefacts, logs, screenshots that confirm the observation.]

> 📸 Screenshot/PoC: Insert evidence here

```
[Command output, log excerpt, or tool output demonstrating the finding]
```

#### Business Impact

- **[Impact 1]:** [Business consequence]
- **[Impact 2]:** [Detection gap consequence — what an attacker could have done]
- **[Impact 3]:** [Regulatory/compliance consequence]
- **[Impact 4]:** [Reputational/operational consequence]

#### Remediation

- **Immediate:** [Specific technical fix]
- **Short-Term (30 days):** [Monitoring/detection improvement — SIEM rule, EDR configuration]
- **Long-Term:** [Architectural or process change]
- **Detection Engineering:** [Suggested SIEM/EDR detection rule — e.g. alert on LSASS access by non-system process]
- **Reference:** [MITRE ATT&CK mitigation URL / vendor guidance]

[Repeat O-002, O-003, etc. for each observation]

---

# 4. Blue Team Assessment

## 4.1 Detection Coverage

| Phase | Activities | Detected | Alerted | Responded | MTTD |
|---|---|---|---|---|---|
| Initial Access | Phishing / credential capture | [Y/N] | [Y/N] | [Y/N] | [HH:MM] |
| Execution | Payload execution / beacon | [Y/N] | [Y/N] | [Y/N] | [HH:MM] |
| Persistence | Scheduled task / registry | [Y/N] | [Y/N] | [Y/N] | [HH:MM] |
| Privilege Escalation | Service misconfiguration | [Y/N] | [Y/N] | [Y/N] | [HH:MM] |
| Lateral Movement | Pass-the-Hash / SMB | [Y/N] | [Y/N] | [Y/N] | [HH:MM] |
| C2 | HTTPS beacon / DNS tunnel | [Y/N] | [Y/N] | [Y/N] | [HH:MM] |
| Exfiltration | HTTPS data staging | [Y/N] | [Y/N] | [Y/N] | [HH:MM] |

**Overall Blue Team Detection Rate:** [X%]

## 4.2 Detection Engineering Recommendations

[3–5 specific SIEM/EDR rules that would have detected the red team's activity. Format: Rule Name / Log Source / Detection Logic / MITRE Technique]

---

# 5. Remediation Roadmap

Prioritised remediation schedule with time-bound deadlines calculated from {{date}}.

[AI: Insert table with Priority | ID | Observation | Severity | SLA | Owner | Detection Improvement | Status]

---

# 6. Appendix

## A. MITRE ATT&CK Coverage Heatmap Summary

| Tactic | Techniques Executed | Detected | Detection Rate |
|---|---|---|---|
| Reconnaissance | [X] | [Y] | [Z%] |
| Initial Access | [X] | [Y] | [Z%] |
| Execution | [X] | [Y] | [Z%] |
| Persistence | [X] | [Y] | [Z%] |
| Privilege Escalation | [X] | [Y] | [Z%] |
| Defense Evasion | [X] | [Y] | [Z%] |
| Credential Access | [X] | [Y] | [Z%] |
| Discovery | [X] | [Y] | [Z%] |
| Lateral Movement | [X] | [Y] | [Z%] |
| Collection | [X] | [Y] | [Z%] |
| Exfiltration | [X] | [Y] | [Z%] |
| **TOTAL** | **[X]** | **[Y]** | **[Z%]** |

## B. Tools and Infrastructure Used

| Tool | Category | Purpose | Detected |
|---|---|---|---|
| [C2 Framework] | C2 | Command and Control | [Y/N] |
| Impacket | Post-Exploitation | SMB/WMI lateral movement | [Y/N] |
| Mimikatz / SafetyKatz | Credential Access | LSASS credential dumping | [Y/N] |
| BloodHound / SharpHound | Discovery | AD attack path mapping | [Y/N] |
| Nmap | Reconnaissance | Network scanning | [Y/N] |
| Responder | Credential Access | NBNS/LLMNR poisoning | [Y/N] |
| CrackMapExec | Lateral Movement | SMB enumeration and execution | [Y/N] |

## C. Timeline of Events

| Date/Time (UTC) | Event | System | Detected |
|---|---|---|---|
| [YYYY-MM-DD HH:MM] | [Event description] | [System] | [Y/N] |

## D. Threat Actor Emulation Profile

**Simulated Actor:** [APT29 / FIN7 / SCATTERED SPIDER / Custom eCrime profile]
**Motivation:** [Financial / Espionage / Destruction]
**Sophistication Level Required:** [Nation-state / Advanced / Intermediate / Basic]
**Actual Sophistication Needed:** [What level was actually sufficient to compromise the target]
**Known Campaigns:** [Reference to real-world campaigns this actor has conducted]

