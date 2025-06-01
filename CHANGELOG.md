# Changelog — VAJRA

All notable changes to this project are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.4.0] — 2026-03-31 · Public Release

First public open-source release. Fully decoupled from any proprietary platform.

### Changed
- Removed all organisation-specific API integrations — now 100% platform-independent
- `ANTHROPIC_API_KEY` → `AI_API_KEY`, `IBKR_MODE`/`IBKR_USERNAME` → removed entirely
- `AI_PROVIDER` env var introduced — selects the active AI backend
- Provider router (`_call_provider`) rewritten using raw `httpx` — no extra SDK installs needed for most providers
- IBKR-branded phishing template renamed to `VAJRA-PHISHING-TEMPLATE.docx`
- `README.md` fully rewritten for public audience

### Added
- **Multi-provider AI support** — 14 providers out of the box, zero extra installs for 13 of them:
  - Anthropic (Claude), OpenAI (ChatGPT), xAI (Grok), Groq, Together AI,
    Ollama, LM Studio, DeepSeek, OpenRouter, Perplexity, Azure OpenAI,
    Mistral, Cohere (all via httpx)
  - Google Gemini (requires `google-generativeai`)
- `_OPENAI_COMPAT_URLS` lookup — new provider = one line added to a dict
- `.env.example` with a complete commented example for every supported provider
- `CHANGELOG.md` (this file)

### Fixed
- Unknown `AI_PROVIDER` values now fall back gracefully with a clear error message
- Status API (`/api/status`) returns `provider` field instead of IBKR-specific fields

---

## [1.3.0] — 2025 · Team Features & Report Sharing

### Added
- **Multi-user system** — admin, analyst, and viewer roles
- **Report visibility controls** — private, team, public per-report
- **Explicit report sharing** — `report_shares` table, share with specific users
- **User management** — create, disable, enable, delete users from the admin panel
- **Account lockout** — brute-force protection (10 attempts / 5 min, per IP and username)
- **Session fixation fix** — `session.clear()` before setting new session on login
- **Audit fields** — `created_by`, `visibility` added to reports table
- **Secure cookies** — `HttpOnly`, `SameSite=Strict`, optional `Secure` flag via `HTTPS=true`
- **Rate limiting on generation** — max 10 reports per 5 minutes per user
- **User disable/enable** — `is_disabled` column; disabled accounts cannot log in

### Changed
- Passwords upgraded to PBKDF2-HMAC-SHA256 with 260,000 iterations and per-user salt
- Admin password now synced from `ADMIN_PASSWORD` env var on every boot
- Report list filtered by access control — users only see reports they can access

---

## [1.2.0] — 2025 · Large Assessment Engine & Tool Import

### Added
- **Chunked parallel generation** — assessments with 10+ findings split into batches
  - Skeleton call (exec summary + findings table) runs first
  - Finding batches run in parallel (up to 6 concurrent AI calls)
  - Progress polling via `/api/generate/progress/<job_id>`
- **Tool import parsers** — upload Nessus `.nessus`, Burp Suite `.xml`, Nmap `.xml`
  - Auto-detects format, extracts structured findings
- **Manual report generation** — structured DOCX without AI (`/api/generate/manual`)
- **Knowledge base smart selection** — word-boundary signal matching loads only relevant KB files per assessment type
- **Custom KB upload** — drop `.md`/`.txt` files into `knowledge/` at runtime
- **Logo embedding** — company and tester logos embedded in DOCX cover page
- **`defusedxml`** — XXE-safe XML parsing for tool imports
- **`waitress`** — production WSGI server replaces Flask dev server

### Changed
- `FINDINGS_PER_CHUNK = 3` — 3 findings per AI call reduces gateway timeout risk
- Knowledge base selection now uses regex word-boundary matching to avoid false positives (e.g. "ad" in "loaded", "web" in "webhook")

---

## [1.1.0] — 2024–2025 · Red Team & Phishing Report Types

### Added
- **Red Team report type** — CREST STAR / CBEST / TIBER-EU format
  - MITRE ATT&CK TTP mapping table
  - Kill chain narrative sections
  - Blue team detection assessment
  - Observation blocks with phase, technique, dwell time
- **Phishing Campaign report type** — NIST / SANS / CREST format
  - Campaign metrics table (sent, delivered, opened, clicked, submitted, MFA bypassed)
  - Department breakdown table
  - Email security controls assessment (SPF, DKIM, DMARC)
  - Phishing Resilience Score calculation
  - Campaign-specific DB fields: `reviewer`, `approver`, `campaign_period`, `platform`,
    `campaigns_json`, `distribution_list`, `phished_employees`
- **Custom `.docx` template support** — `docx_template_filler.py` fills real Word templates
- **Custom `.md` template support** — AI follows user-supplied markdown structure
- **Placeholder injection** — `{{client}}`, `{{date}}`, `{{tester}}` etc. replaced before AI sees template
- **`generate.js` v10.0** — complete DOCX builder rewrite fixing 12 identified issues:
  - Finding ID corruption (`F — 001` → `F-001`) fixed
  - Unified metadata table per finding
  - TOC matches actual document structure
  - Code blocks with monospace shading
  - Report-type colour themes (Pentest=navy, Red Team=crimson, Phishing=amber)
  - Cover page with logo support, Word dark-mode safe
- **Engagement reference, classification, report version** fields added to all report types
- **PDF export** — multi-strategy fallback: LibreOffice → pandoc+wkhtmltopdf → pandoc+LaTeX → weasyprint

### Changed
- System prompt updated with strict section naming rules for DOCX parser compatibility
- `REPORT_PROMPTS` expanded to include structured templates for all three report types

---

## [1.0.0] — 2024 · Initial Build

First working version — penetration test report generation from raw findings.

### Added
- **Flask web application** — single-file backend, runs on `localhost:5000`
- **Penetration test report generation** — CREST / PTES / OWASP WSTG v4.2 / NIST SP 800-115
- **Findings input** — paste raw notes, AI structures them into a professional report
- **Report sections** — Executive Summary, Engagement Overview, Findings (with CVSS, CWE, OWASP, PoC, Remediation), Remediation Roadmap, Appendix
- **DOCX export** — `generate.js` Node.js builder using `docx` library
- **SQLite report history** — `penreport.db`, stores generated content and metadata
- **Knowledge base** — 14 domain-specific `.md` files loaded as AI context:
  - Core reference, severity definitions, CWE reference, remediation boilerplate
  - Web application, API security, Active Directory, Cloud security, Mobile
  - Network infrastructure, Red team, Phishing, Wireless/IoT, OWASP Top 10
- **Login system** — single admin account, session-based auth
- **Nessus / Burp / Nmap XML parsers** — tool import to structured findings text
- **Environment-based config** — `.env` file for API key, endpoint, model, SSL settings

---

## Notes

- Version dates reflect when features were built, not necessarily when they were pushed to a public repository.
- VAJRA was developed as an internal tooling project starting in 2024 and open-sourced in March 2026.
