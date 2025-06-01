# VAJRA — Custom Template Guide

## How VAJRA Uses Templates

VAJRA uses a **Node.js DOCX generator** (`docx_builder/generate.js`) as its primary report engine.
It builds the report from scratch using a fixed professional layout — it does **not** inject content
into an existing DOCX template. Templates selected in the UI are recorded for reference but the
generated DOCX always uses the built-in VAJRA format.

> **In short:** VAJRA generates its own fully-formatted DOCX. You do not need a template at all.
> The "Template" dropdown is reserved for future custom-injection support.

---

## What the AI-Generated Markdown Must Contain

The AI output (and your raw notes) must follow this structure so VAJRA can parse findings correctly:

### Required Section Headings

```markdown
# Penetration Test Report

## Executive Summary
...your executive summary text...

## Findings Overview
...optional summary table...

## Vulnerabilities

### F-01 — [Finding Title]
**Severity:** Critical | High | Medium | Low | Info
**CVSS:** 9.8
**CWE:** CWE-89
**Host:** app.example.com/api/login

#### Description
...

#### Evidence / PoC
...

#### Impact
...

#### Remediation
...

### F-02 — [Next Finding Title]
...

## Remediation Roadmap
...

## Appendix
...
```

---

## Finding Block — Full Format

Each finding must start with a heading matching one of these patterns:

```
### F-01 — SQL Injection in Login API
### F-02 — Stored XSS in Comments
### Finding 1: Broken Authentication
### Finding #3 — IDOR on /api/users
```

### Metadata fields VAJRA reads automatically:

| Field | Format | Example |
|-------|--------|---------|
| Severity | `**Severity:** High` | Critical, High, Medium, Low, Info |
| CVSS | `**CVSS:** 9.8` | Any numeric score |
| CVE/CWE | `**CWE:** CWE-89` | CVE-2023-XXXX or CWE-XX |
| Host/URL | `**Host:** app.example.com` | Any hostname or URL |
| OWASP | `**OWASP:** A03:2021` | OWASP category |

### Table-style metadata (also parsed):

```markdown
| Field | Details |
|-------|---------|
| **Severity** | High |
| **CVSS v3.1 Score** | 7.5 (High) |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **CWE** | CWE-79 |
| **Affected Host** | `app.example.com` |
| **Affected URL** | `app.example.com/search.php` |
```

### Subsections VAJRA recognises:

```markdown
#### Description
Plain text. Supports **bold**, `code`, bullet lists.

#### Evidence / PoC
Paste your payload, request/response, tool output.
A "📸 SCREENSHOT PLACEHOLDER" box is automatically inserted here in the DOCX.

#### Impact
Business risk, data exposure scenarios.

#### Remediation
Numbered or bulleted fix steps. Code blocks supported.
```

---

## Supported Markdown in Content

| Element | Syntax | Notes |
|---------|--------|-------|
| Bold | `**text**` | Renders as bold run |
| Inline code | `` `code` `` | Courier New, blue |
| Code block | ` ```lang ` … ` ``` ` | Grey box, Courier New |
| Bullet list | `- item` or `* item` | Proper Word bullets |
| Numbered list | `1. item` | Proper Word numbering |
| Table | `\| col \| col \|` | Navy header, alt-row shading |
| Blockquote | `> text` | Italic, left blue border |
| H1–H4 | `# ## ### ####` | Each H1 starts a new page |

---

## PoC Screenshots — How to Add Them

Every finding's Evidence section includes a placeholder box in the exported DOCX:

```
📸  SCREENSHOT / PoC PLACEHOLDER  — Replace this box with your screenshot
In Microsoft Word: Insert → Pictures → This Device
In LibreOffice: Insert → Image
```

**To replace it:**
1. Open the exported `.docx` in Word or LibreOffice
2. Click on the placeholder box
3. **Word:** Insert → Pictures → This Device → select your screenshot
4. **LibreOffice:** Insert → Image → select your screenshot
5. Resize as needed — crop to focus on the relevant part

---

## Logos

Upload via the **Company Logos** sidebar tab, or via the logo slots on the New Report panel.

- **Client/Company logo** → appears on the left of the cover page
- **Assessor/Firm logo** → appears on the right of the cover page
- Supported formats: **PNG, JPG, JPEG, GIF, BMP** (SVG is not supported by Word's DOCX format)
- Recommended: PNG with transparent background, minimum 300×120px

Logos are stored in `ui/static/logos/` and automatically embedded into every new DOCX export.

---

## Report Sections Generated Automatically

Every VAJRA report includes:

1. **Cover Page** — type label, client/assessor logos, metadata table, confidentiality bar
2. **Document Control** — confidentiality notice, revision history, engagement details
3. **Executive Summary** — from your AI-generated content
4. **Findings Overview** — horizontal bar chart + proportional colour strip by severity
5. **Vulnerabilities** — one card per finding with title bar, metadata, description, PoC placeholder, impact, remediation
6. **Remediation Roadmap** — priority table with SLA timelines
7. **Appendix / other sections** — any additional H2 sections in the AI output

Each H1 section automatically starts on a new page.

---

## Future: Custom Template Injection (Planned)

If you want VAJRA to inject content into **your own branded DOCX template**, the template must:

1. Use standard Word paragraph styles: `Heading 1`, `Heading 2`, `Heading 3`, `Normal`
2. Contain section placeholder text matching the section names VAJRA looks for:
   - `{{executive_summary}}`
   - `{{findings_overview}}`
   - `{{vulnerabilities}}`
   - `{{remediation_roadmap}}`
3. Be saved as `.docx` and uploaded via the Templates tab
4. Be selected in the Template dropdown before generating

This feature will be available in a future release. For now, the default VAJRA format is used.
