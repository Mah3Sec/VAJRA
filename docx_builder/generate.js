"use strict";
/**
 * VAJRA — generate.js  v10.0
 * Complete rewrite fixing all 12 identified issues:
 *  1. Finding ID corruption (F — 001 → F-001)
 *  2. Duplicate findings sections eliminated — body prose stripped, DOCX builder is single source
 *  3. Finding metadata in ONE unified table per finding
 *  4. Impact/Remediation empty → fixed content extraction
 *  5. Assessment team parsed correctly (Lead extracted separately)
 *  6. TOC matches actual structure
 *  7. Findings section naming consistent
 *  8. Code blocks styled with monospace shading
 *  9. All AI findings rendered (not just 2)
 * 10. CVSS vector complete
 * 11. Cover logo placeholder shown when no logo
 * 12. Cover background: pure white, Word dark-mode safe
 * + Theme colours by report type: Pentest=navy, RedTeam=red, Phishing=amber
 * Author: Mahendra Purbia
 */
const fs   = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, HeadingLevel, AlignmentType, BorderStyle, WidthType,
  ShadingType, LevelFormat, PageNumber, VerticalAlign, ImageRun,
  ExternalHyperlink, InternalHyperlink, Bookmark, UnderlineType,
  TabStopType, LeaderType, PageBreak, Run,
} = require("docx");

let _ni=0;
function freshNum(){return "olist"+(_ni++%80);}

const inputFile  = process.argv[2];
const outputFile = process.argv[3];
if (!inputFile || !outputFile) { console.error("Usage: node generate.js input.json output.docx"); process.exit(1); }

let raw;
try { raw = JSON.parse(fs.readFileSync(inputFile,"utf8")); }
catch(e) { console.error("ERR:Cannot read input: "+e.message); process.exit(1); }

const MD   = String(raw.content || "");
const meta = raw.meta || {};
const COMP = raw.companyLogo || null;
const TEST = raw.testerLogo  || null;

// ─── REPORT TYPE THEME ───────────────────────────────────────────
const RTYPE = (meta.report_type||"pentest").toLowerCase();

const THEME = {
  pentest: {
    accent:  "1B2A4A",   // navy
    accent2: "2E75B6",   // steel blue
    accentLt:"EEF5FF",   // light blue tint
    barBg:   "1B2A4A",   // finding title bar
    h1Color: "1B2A4A",
    h2Color: "1F5C99",
    typeLabel:"Penetration Test Report",
    tag:     "PENTEST",
  },
  redteam: {
    accent:  "8B0000",   // deep red
    accent2: "C0392B",   // bright red
    accentLt:"FEF0F0",   // light red tint
    barBg:   "8B0000",
    h1Color: "8B0000",
    h2Color: "C0392B",
    typeLabel:"Red Team Engagement Report",
    tag:     "RED TEAM",
  },
  phishing: {
    accent:  "7A4800",   // amber/dark orange
    accent2: "E67E22",   // orange
    accentLt:"FEF9EE",   // light amber tint
    barBg:   "7A4800",
    h1Color: "7A4800",
    h2Color: "E67E22",
    typeLabel:"Phishing Campaign Assessment",
    tag:     "PHISHING",
  },
};
const T = THEME[RTYPE] || THEME.pentest;

// ─── CONSTANTS ───────────────────────────────────────────────────
const PW = 10080;  // US Letter content width in DXA (1080 margins each side)
const CVSS_BASE = "https://www.first.org/cvss/calculator/3.1#";

const C = {
  navy:  "1B2A4A",  blue:  "1F5C99",  lb:    "2E75B6",
  green: "1E5C2E",  greenBg:"F0FAF2",
  gray:  "555555",  dark:  "222222",  muted: "777777",  white: "FFFFFF",
  bg0:   "F7F9FC",  bg1:   "EEF5FF",  border:"C8D4E0",  border2:"A8BCCE",
  talt:  "F2F5FA",  thead: "1B2A4A",
  crit:  "8B0000",  critBg:"FEF0F0",
  high:  "9B3A00",  highBg:"FEF5EF",
  med:   "7A5900",  medBg: "FEFAEE",
  low:   "1E5C2E",  lowBg: "F0FAF2",
  info:  "1A3E6E",  infoBg:"EEF5FF",
  logoBox:"E8EEF4",
  accent: T.accent, accent2: T.accent2, accentLt: T.accentLt,
};

// ─── SEVERITY ────────────────────────────────────────────────────
function normSev(s) {
  const r = String(s||"").replace(/[^\w\s]/g,"").toLowerCase().trim();
  if (r.includes("crit")) return "Critical";
  if (r.includes("high")) return "High";
  if (r.includes("med"))  return "Medium";
  if (r.includes("low"))  return "Low";
  return "Info";
}
const SEV_HEX = s => ({Critical:C.crit,High:C.high,Medium:C.med,Low:C.low}[normSev(s)] || C.info);
const SEV_BG  = s => ({Critical:C.critBg,High:C.highBg,Medium:C.medBg,Low:C.lowBg}[normSev(s)] || C.infoBg);
const SEV_SLA = s => ({Critical:"24-48 hours",High:"7 days",Medium:"30 days",Low:"90 days"}[normSev(s)] || "Best effort");

// ─── PARSE ASSESSMENT TEAM ───────────────────────────────────────
// Fix Issue 5: extract Lead from team string like "Alex Carter (Lead) - Bob Smith (Analyst)"
function parseTeam(teamStr) {
  const s = String(teamStr||"").trim();
  if (!s) return {lead:"—", team:"—", teamList:[]};
  // Split on " - " or ", " 
  const parts = s.split(/\s*[-,]\s+/).map(p=>p.replace(/^-\s*/,"").trim()).filter(Boolean);
  if (parts.length === 1) return {lead:s, team:s, teamList:[s]};
  // Find lead — look for "(Lead" keyword
  const leadPart = parts.find(p=>/lead/i.test(p)) || parts[0];
  const leadName = leadPart.replace(/\s*\([^)]*\)/g,"").trim();
  return {lead:leadName, team:s, teamList:parts};
}

// ─── BORDER / SHADE ──────────────────────────────────────────────
const bd   = (c, sz=4) => ({ style:BorderStyle.SINGLE, size:sz, color:c });
const noBd = ()        => ({ style:BorderStyle.NONE,   size:0,  color:"FFFFFF" });
const NB   = ()        => ({ top:noBd(), bottom:noBd(), left:noBd(), right:noBd() });
const AB   = (c,sz=4)  => ({ top:bd(c,sz), bottom:bd(c,sz), left:bd(c,sz), right:bd(c,sz) });
const LB   = (c,sz=8)  => ({ top:noBd(), bottom:noBd(), left:bd(c,sz), right:noBd() });

// ─── TEXT HELPERS ────────────────────────────────────────────────
const R  = (t,o={}) => new TextRun({text:String(t||""),font:"Calibri",size:22,color:C.dark,...o});
const B  = (t,o={}) => R(t,{bold:true,...o});
const Mn = (t,o={}) => new TextRun({text:String(t||""),font:"Courier New",size:18,color:C.lb,...o});

function cvssLink(label, url) {
  return new ExternalHyperlink({ link:url, children:[
    new TextRun({text:String(label),font:"Calibri",size:20,color:C.lb,
      underline:{type:UnderlineType.SINGLE,color:C.lb}})
  ]});
}

function inline(text, base={}) {
  const cleaned = String(text||"").replace(/\[([^\]]+)\]\(#[^)]+\)/g,"$1");
  return cleaned.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean).map(p => {
    if (p.startsWith("**")&&p.endsWith("**")) return R(p.slice(2,-2),{bold:true,...base});
    if (p.startsWith("`") &&p.endsWith("`"))  return Mn(p.slice(1,-1));
    return R(p,base);
  });
}

// ─── PARAGRAPH HELPERS ───────────────────────────────────────────
const P0  = (ch,o={}) => new Paragraph({spacing:{before:0,after:0},   children:ch,...o});
const P   = (ch,o={}) => new Paragraph({spacing:{before:0,after:120},  children:ch,...o});
const SP  = (n=160)   => new Paragraph({spacing:{before:0,after:n},    children:[]});

// ─── HEADING HELPERS (theme-coloured) ────────────────────────────
// Slugify title to bookmark ID (used by H1 and TOC InternalHyperlink)
function slugBM(t){return "bm_"+t.toLowerCase().replace(/[^a-z0-9]+/g,"_").slice(0,40);}

const H1 = (t) => new Paragraph({
  heading:HeadingLevel.HEADING_1, pageBreakBefore:true,
  spacing:{before:0,after:240},
  children:[
    new Bookmark({id:slugBM(t), children:[R(t,{bold:true,size:40,color:T.accent})]}),
  ]
});
const H2 = (t) => new Paragraph({
  heading:HeadingLevel.HEADING_2,
  spacing:{before:400,after:140},
  children:[R(t,{bold:true,size:30,color:T.accent2})]
});
const H3 = (t) => new Paragraph({
  heading:HeadingLevel.HEADING_3,
  spacing:{before:280,after:100},
  children:[R(t,{bold:true,size:26,color:T.accent})]
});
const H4 = (t) => new Paragraph({
  heading:HeadingLevel.HEADING_4,
  spacing:{before:180,after:60},
  children:[R(t,{bold:true,size:22,color:C.gray})]
});

// ─── CELL HELPER ─────────────────────────────────────────────────
function cell(children, {w,bg,borders,vAlign,margins}={}) {
  return new TableCell({
    width:        w  ? {size:w,type:WidthType.DXA} : undefined,
    shading:      bg ? {fill:bg,type:ShadingType.CLEAR} : undefined,
    borders:      borders  || NB(),
    verticalAlign:vAlign   || VerticalAlign.TOP,
    margins:      margins  || {top:80,bottom:80,left:120,right:120},
    children: Array.isArray(children) ? children : [children],
  });
}
const hdrCell = (t,w,bg) => cell(
  P0([B(t,{color:C.white,size:20})]),
  {w,bg:bg||T.accent,borders:NB(),margins:{top:100,bottom:100,left:140,right:140}}
);

// ─── IMAGE LOADER ────────────────────────────────────────────────
function loadLogo(fp, maxW=360, maxH=120) {
  if (!fp) return null;
  try {
    const p = path.resolve(fp);
    if (!fs.existsSync(p)) return null;
    const ext = path.extname(p).toLowerCase();
    if (![".png",".jpg",".jpeg",".gif",".bmp",".webp"].includes(ext)) return null;
    const buf = fs.readFileSync(p);
    if (buf.length < 100) return null;
    const type = ext === ".png" ? "png" : ext === ".gif" ? "gif" : "jpg";
    let imgW = maxW, imgH = maxH;
    try {
      if (ext === ".png" && buf.length > 24) {
        const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
        if (w > 0 && h > 0) {
          const ratio = w / h;
          imgW = maxW; imgH = Math.round(maxW / ratio);
          if (imgH > maxH) { imgH = maxH; imgW = Math.round(maxH * ratio); }
        }
      } else if ((ext === ".jpg"||ext === ".jpeg") && buf.length > 4) {
        let i = 2;
        while (i < buf.length - 8) {
          if (buf[i] === 0xFF && (buf[i+1] & 0xF0) === 0xC0 && buf[i+1] !== 0xFF) {
            const h = buf.readUInt16BE(i+5), w = buf.readUInt16BE(i+7);
            if (w > 0 && h > 0) {
              imgW = maxW; imgH = Math.round(maxW / h * h);
              const ratio = w / h;
              imgW = maxW; imgH = Math.round(maxW / ratio);
              if (imgH > maxH) { imgH = maxH; imgW = Math.round(maxH * ratio); }
            }
            break;
          }
          i++;
        }
      }
    } catch(e2) {}
    return new ImageRun({data:buf, type, transformation:{width:imgW, height:imgH}});
  } catch(e) { return null; }
}

// ─── COVER PAGE 1 — Logo + Title ─────────────────────────────────
// Fix Issue 11/12: white background, large logo centred, required title below
// Cover uses full-bleed top/bottom accent bars (these invert in Word dark mode — expected)
// ─── COVER PAGE 1 ────────────────────────────────────────────────
// Cover section uses ZERO margins on all sides (see section definition below).
// Full page width = 12240 DXA. Content is centred using inner spacing.
// PW_C = full page width for full-bleed bars
// INNER = inner content width (same as body PW) for text/logo alignment
const PW_C   = 12240;  // full page width — bars bleed edge-to-edge
const INNER  = 10080;  // inner content = same as body content width
const LPAD   = (PW_C - INNER) / 2;  // = 1080 DXA left pad for inner content

function buildCoverPage1(meta, compPath, testPath) {
  const typeLabel = T.typeLabel;
  const compImg = loadLogo(compPath, 480, 150);
  const items = [];

  // ══ TOP BAR — full bleed, flush to page top (zero margin above) ══
  items.push(new Table({
    width:{size:PW_C,type:WidthType.DXA}, columnWidths:[PW_C], borders:NB(),
    rows:[new TableRow({
      height:{value:380,rule:"exact"},
      children:[cell(P0([R(" ")]),
        {w:PW_C,bg:T.accent,borders:NB(),margins:{top:0,bottom:0,left:0,right:0}})]
    })]
  }));

  // ── Push logo to upper-centre of page ──
  items.push(SP(2800));

  // ── Client Logo centred within inner content zone ──
  const logoBoxW = 4800, logoBoxH = 1400;
  const logoLgap = Math.max(0, Math.floor((PW_C - logoBoxW) / 2));
  const logoRgap = Math.max(0, PW_C - logoBoxW - logoLgap);

  if (compImg) {
    // Logo present — use centred paragraph (within inner zone)
    items.push(new Table({
      width:{size:PW_C,type:WidthType.DXA},
      columnWidths:[logoLgap, logoBoxW, logoRgap], borders:NB(),
      rows:[new TableRow({
        height:{value:logoBoxH,rule:"exact"},
        children:[
          cell(P0([R(" ")]),{w:logoLgap,borders:NB()}),
          cell(new Paragraph({alignment:AlignmentType.CENTER,spacing:{before:0,after:0},children:[compImg]}),
            {w:logoBoxW,borders:NB(),vAlign:VerticalAlign.CENTER}),
          cell(P0([R(" ")]),{w:logoRgap,borders:NB()}),
        ]
      })]
    }));
    items.push(SP(600));
    // No company name when logo is shown
  } else {
    // No logo — show dashed placeholder box
    items.push(new Table({
      width:{size:PW_C,type:WidthType.DXA},
      columnWidths:[logoLgap, logoBoxW, logoRgap], borders:NB(),
      rows:[new TableRow({
        height:{value:logoBoxH,rule:"exact"},
        children:[
          cell(P0([R(" ")]),{w:logoLgap,borders:NB()}),
          cell(new Paragraph({alignment:AlignmentType.CENTER,spacing:{before:0,after:0},
            children:[R("[ Upload Client Logo ]",{size:24,color:C.border2,italics:true})]}),
            {w:logoBoxW,bg:"F8FAFC",
             borders:{top:{style:BorderStyle.DASHED,size:8,color:C.border2},
                      bottom:{style:BorderStyle.DASHED,size:8,color:C.border2},
                      left:{style:BorderStyle.DASHED,size:8,color:C.border2},
                      right:{style:BorderStyle.DASHED,size:8,color:C.border2}},
             vAlign:VerticalAlign.CENTER,margins:{top:0,bottom:0,left:240,right:240}}),
          cell(P0([R(" ")]),{w:logoRgap,borders:NB()}),
        ]
      })]
    }));
    items.push(SP(600));
    // Show client name only when no logo
    const clientName = String(meta.client||"").trim();
    if (clientName) {
      items.push(new Paragraph({
        alignment:AlignmentType.CENTER,
        spacing:{before:0,after:0},
        children:[R(clientName,{size:32,color:C.muted,bold:false})],
      }));
      items.push(SP(120));
    }
  }

  // ── Report type title ──
  items.push(new Paragraph({
    alignment:AlignmentType.CENTER,
    spacing:{before:0,after:160},
    children:[B(typeLabel,{size:60,color:T.accent})],
  }));

  // ── Engagement ref line ──
  const engRef = meta.engagement_ref || `ENG-${(meta.date||"2026").slice(0,4)}-001`;
  items.push(new Paragraph({
    alignment:AlignmentType.CENTER,
    spacing:{before:0,after:0},
    children:[R(`${engRef}  ·  ${meta.date||""}`,{size:20,color:C.muted})],
  }));

  return items;
}

// ── Cover page footer bar — rendered as DOCX footer so always flush at page bottom ──
function buildCoverFooter(meta, testPath) {
  const b1 = Math.floor(PW_C * 0.62), b2 = PW_C - b1;
  const testImg = testPath ? loadLogo(testPath, 240, 42) : null;
  const rightPara = testImg
    ? new Paragraph({spacing:{before:0,after:0}, alignment:AlignmentType.RIGHT, children:[testImg]})
    : new Paragraph({spacing:{before:0,after:0}, alignment:AlignmentType.RIGHT,
        children:[R(meta.report_version||"1.0 — Final",{color:"8FA8C8",size:18,italics:true})]});
  return new Footer({
    children:[
      new Table({
        width:{size:PW_C, type:WidthType.DXA}, columnWidths:[b1, b2], borders:NB(),
        rows:[new TableRow({
          height:{value:520, rule:"exact"},
          children:[
            cell(new Paragraph({spacing:{before:0,after:0}, alignment:AlignmentType.LEFT,
              children:[B("CONFIDENTIAL — NOT FOR DISTRIBUTION",{color:C.white,size:19})]}),
              {w:b1, bg:T.accent, borders:NB(), vAlign:VerticalAlign.CENTER,
               margins:{top:0,bottom:0,left:1200,right:80}}),
            cell(rightPara,
              {w:b2, bg:T.accent, borders:NB(), vAlign:VerticalAlign.CENTER,
               margins:{top:0,bottom:0,left:80,right:800}}),
          ]
        })]
      })
    ]
  });
}

// ─── COVER PAGE 2 — Report Information ───────────────────────────
function buildCoverPage2(meta) {
  const teamInfo = parseTeam(meta.assessment_team || meta.tester);
  const engRef = meta.engagement_ref || `ENG-${(meta.date||"2026").slice(0,4)}-001`;
  const items = [];

  items.push(SP(400));
  items.push(new Paragraph({
    alignment: AlignmentType.CENTER, spacing:{before:0, after:80},
    children: [B("REPORT INFORMATION",{size:36, color:T.accent})],
  }));
  items.push(new Table({
    width:{size:PW,type:WidthType.DXA}, columnWidths:[PW], borders:NB(),
    rows:[new TableRow({height:{value:24,rule:"exact"},children:[
      cell(P0([R(" ")]),{w:PW,bg:T.accent,borders:NB(),margins:{top:0,bottom:0,left:0,right:0}})
    ]})]
  }));
  items.push(SP(400));

  const KW=3000, VW=PW-KW;
  const rows = [
    ["Prepared For:",     meta.client || "—"],
    ["Prepared By:",      teamInfo.lead],   // Fix Issue 5: Lead only
    ["Assessment Team:",  teamInfo.team],
    ["Report Date:",      meta.date || "—"],
    ["Engagement Ref:",   engRef],
    ["Target System:",    meta.target_system || meta.scope || "—"],
    ["Project Tested From:", meta.tested_from || "—"],
    ["Classification:",   meta.classification || "CONFIDENTIAL — NOT FOR DISTRIBUTION"],
    ["Version:",          meta.report_version || "1.0 — Final"],
  ];

  items.push(new Table({
    width:{size:PW,type:WidthType.DXA}, columnWidths:[KW,VW], borders:NB(),
    rows: rows.map(([k,v], i) => new TableRow({children:[
      cell(new Paragraph({spacing:{before:120,after:120},children:[B(k,{size:22,color:T.accent})]}),
        {w:KW, bg:i%2===0?C.bg0:C.white,
         borders:{...NB(),bottom:bd(C.border,2)},margins:{top:0,bottom:0,left:180,right:120}}),
      cell(new Paragraph({spacing:{before:120,after:120},children:[R(v,{size:22})]}),
        {w:VW, bg:i%2===0?C.bg0:C.white,
         borders:{...NB(),bottom:bd(C.border,2)},margins:{top:0,bottom:0,left:120,right:120}}),
    ]}))
  }));

  items.push(SP(500));
  items.push(new Table({
    width:{size:PW,type:WidthType.DXA}, columnWidths:[PW], borders:NB(),
    rows:[new TableRow({children:[
      cell(new Paragraph({spacing:{before:120,after:120},children:[
        R("This document is classified ", {size:19, color:C.gray}),
        B("CONFIDENTIAL",                 {size:19, color:C.crit}),
        R(" and is intended solely for the named recipient(s). Unauthorised disclosure is strictly prohibited.", {size:19, color:C.gray}),
      ]}),{w:PW, bg:"FEF0F0",
       borders:{top:bd(C.crit,4),bottom:bd(C.crit,4),left:bd(C.crit,8),right:bd(C.border,2)},
       margins:{top:0,bottom:0,left:200,right:200}}),
    ]})],
  }));

  return items;
}

// ─── DOCUMENT CONTROL ────────────────────────────────────────────
function buildDocControl(meta) {
  const teamInfo = parseTeam(meta.assessment_team || meta.tester);
  const engRef = meta.engagement_ref || `ENG-${(meta.date||"2026").slice(0,4)}-001`;
  const KW=2600, VW=PW-KW;

  // Distribution list — Fix Issue 5: parse team members into rows
  const teamRows = teamInfo.teamList.length > 1
    ? teamInfo.teamList.map((member,i) => new TableRow({children:[
        cell(P0([R(member.replace(/\s*\([^)]*\)/g,"").trim(),{size:20})]),{w:3200,bg:i%2===0?C.talt:C.white}),
        cell(P0([R(member.match(/\(([^)]+)\)/)?member.match(/\(([^)]+)\)/)[1]:"Team Member",{size:20})]),{w:2400,bg:i%2===0?C.talt:C.white}),
        cell(P0([R(meta.assessment_team||"Assessment Team",{size:20})]),{w:2400,bg:i%2===0?C.talt:C.white}),
        cell(P0([R("1",{size:20})]),{w:2080,bg:i%2===0?C.talt:C.white}),
      ]}))
    : [new TableRow({children:[
        cell(P0([R(teamInfo.lead,{size:20})]),{w:3200,bg:C.talt}),
        cell(P0([R("Lead Assessor",{size:20})]),{w:2400,bg:C.talt}),
        cell(P0([R(meta.assessment_team||meta.tester||"—",{size:20})]),{w:2400,bg:C.talt}),
        cell(P0([R("1",{size:20})]),{w:2080,bg:C.talt}),
      ]})];

  return [
    H1("Document Control"),
    H2("Confidentiality Notice"),
    P(inline("This report contains confidential and proprietary information belonging solely to the named client. The recipient must not disclose, reproduce, distribute, or transmit this document in any form without prior written authorisation.")),
    P(inline("All findings represent a point-in-time assessment. The security posture of tested systems may have changed since the assessment date.")),
    SP(160),
    H2("Distribution List"),
    new Table({width:{size:PW,type:WidthType.DXA},columnWidths:[3200,2400,2400,2080],
      rows:[
        new TableRow({children:[hdrCell("Recipient",3200),hdrCell("Role",2400),hdrCell("Organisation",2400),hdrCell("Copy",2080)]}),
        ...teamRows,
        new TableRow({children:[
          cell(P0([R(meta.client||"—",{size:20})]),{w:3200}),
          cell(P0([R("Client Representative",{size:20})]),{w:2400}),
          cell(P0([R(meta.client||"—",{size:20})]),{w:2400}),
          cell(P0([R("1",{size:20})]),{w:2080}),
        ]}),
      ]
    }),
    SP(160),
    H2("Revision History"),
    new Table({width:{size:PW,type:WidthType.DXA},columnWidths:[700,2000,2560,4820],
      rows:[
        new TableRow({children:[hdrCell("Ver",700),hdrCell("Date",2000),hdrCell("Author",2560),hdrCell("Description",4820)]}),
        new TableRow({children:[
          // Split "1.0 — Final" -> ver="1.0", label="Final"
          (()=>{const rv=meta.report_version||"1.0";const parts=rv.split(/\s*[—–\-]\s*/);const ver=parts[0].trim();const lbl=parts.slice(1).join(" — ").trim()||"Final";
          return [
            cell(P0([R(ver,{size:20})]),{w:700,bg:C.talt}),
            cell(P0([R(meta.date||"",{size:20})]),{w:2000,bg:C.talt}),
            cell(P0([R(teamInfo.lead||meta.tester||"—",{size:20})]),{w:2560,bg:C.talt}),
            cell(P0([R("Initial release — "+lbl,{size:20})]),{w:4820,bg:C.talt}),
          ];})()
        ].flat()}),
      ]
    }),
    SP(160),
    H2("Engagement Details"),
    new Table({width:{size:PW,type:WidthType.DXA},columnWidths:[KW,VW],borders:NB(),
      rows:[
        ["Client:",        meta.client||"—"],
        ["Assessment Team:",teamInfo.team],
        ["Scope:",         meta.scope||"—"],
        ["Target System:", meta.target_system||meta.scope||"—"],
        ["Tested From:",   meta.tested_from||"—"],
        ["Report Date:",   meta.date||"—"],
        ["Reference:",     engRef],
        ["Classification:",meta.classification||"CONFIDENTIAL — NOT FOR DISTRIBUTION"],
      ].map(([k,v])=>new TableRow({children:[
        cell(new Paragraph({spacing:{before:50,after:50},children:[B(k,{size:19,color:T.accent})]}),
          {w:KW,borders:{...NB(),bottom:bd(C.border,2)}}),
        cell(new Paragraph({spacing:{before:50,after:50},children:[R(v,{size:19})]}),
          {w:VW,borders:{...NB(),bottom:bd(C.border,2)}}),
      ]}))
    }),
  ];
}

// ─── TABLE OF CONTENTS ───────────────────────────────────────────
// Fix Issue 6: TOC matches actual document structure
function buildTOC(reportType) {
  const base = [
    {num:"1.",    title:"Executive Summary",             level:0},
    {num:"2.",    title:"Engagement Overview",           level:0},
    {num:"2.1.",  title:"Scope and Rules of Engagement", level:1},
    {num:"2.2.",  title:"Methodology",                   level:1},
    {num:"2.3.",  title:"Risk Rating Methodology",       level:1},
    {num:"3.",    title:"Findings Overview",             level:0},
    {num:"3.1.",  title:"Findings Summary Table",        level:1},
    {num:"3.2.",  title:"Severity Distribution",         level:1},
    {num:"3.3.",  title:"Risk Proportion",               level:1},
    {num:"4.",    title:"Detailed Findings",             level:0},
    {num:"5.",    title:"Remediation Roadmap",           level:0},
    {num:"6.",    title:"Appendix",                      level:0},
  ];

  const typeExtras = {
    redteam: [
      {num:"2.4.",  title:"Attack Narrative",                    level:1},
      {num:"2.5.",  title:"MITRE ATT&CK Coverage",              level:1},
      {num:"5.1.",  title:"Blue Team Detection Assessment",      level:1},
    ],
    phishing: [
      {num:"2.4.",  title:"Campaign Metrics",                    level:1},
      {num:"2.5.",  title:"Susceptibility Analysis",            level:1},
    ],
  };

  const entries = [...base, ...(typeExtras[reportType]||[])].sort((a,b)=>a.num.localeCompare(b.num));
  // Use a special non-pagebreak H1 for TOC heading
  // Explicit page break before TOC heading
  const tocPageBreak = new Paragraph({spacing:{before:0,after:0},children:[new PageBreak()]});
  const tocHeading = new Paragraph({
    heading:HeadingLevel.HEADING_1,
    spacing:{before:0,after:200},
    children:[new Bookmark({id:"bm_table_of_contents",children:[R("Table of Contents",{bold:true,size:40,color:T.accent})]})]
  });
  const items = [tocPageBreak, tocHeading, SP(80)];
  for (const {num,title,level} of entries) {
    const isMain = level===0;
    // H1 entries get InternalHyperlink to the matching bookmark; sub-entries are plain
    const titleRuns = [
      ...(num?[R(num+"  ",{bold:isMain,size:isMain?24:21,color:isMain?T.accent:C.gray})]:[]),
      R(title,{bold:isMain,size:isMain?24:21,
        color:isMain?T.accent2:C.gray,
        underline:isMain?{type:UnderlineType.SINGLE,color:T.accent2}:undefined}),
    ];
    const linkChildren = isMain
      ? [new InternalHyperlink({anchor:slugBM(title), children:titleRuns})]
      : titleRuns;

    items.push(new Paragraph({
      spacing:{before:isMain?160:80,after:isMain?60:30},
      indent:{left:level===1?480:0},
      tabStops:[{type:TabStopType.RIGHT,position:PW,leader:LeaderType.DOT}],
      children:[
        ...linkChildren,
        new TextRun({text:"\t",font:"Calibri"}),
        R("—",{size:isMain?22:19,color:C.border2}),
      ]
    }));
  }
  items.push(SP(120));
  items.push(new Paragraph({spacing:{before:0,after:0},
    children:[R("ℹ  Right-click → Update Field in Word to populate page numbers",
      {size:17,color:C.muted,italics:true})]}));
  return items;
}

// ─── BAR CHART (theme-coloured bars) ────────────────────────────
function buildBarChart(counts) {
  const SEVS=["Critical","High","Medium","Low","Info"];
  const max=Math.max(...SEVS.map(s=>counts[s.toLowerCase()]||0),1);
  const LW=1900, CW=900, BW=PW-LW-CW;
  const rows=[new TableRow({children:[hdrCell("Severity",LW),hdrCell("Count",CW),hdrCell("Distribution",BW)]})];
  SEVS.forEach((sev,i)=>{
    const cnt=counts[sev.toLowerCase()]||0;
    const hex=SEV_HEX(sev);
    const fill=cnt>0?Math.max(280,Math.round(BW*cnt/max)):0;
    const rest=BW-fill;
    const bg=i%2===0?C.bg0:C.white;
    const colW=fill>0?(rest>0?[fill,rest]:[fill]):[BW];
    const bar=new Table({width:{size:BW,type:WidthType.DXA},columnWidths:colW,borders:NB(),
      rows:[new TableRow({children:[
        ...(fill>0?[cell(P0([R(" ",{size:2})]),{w:fill,bg:hex,borders:NB(),margins:{top:80,bottom:80,left:0,right:0}})]:[]),
        ...(rest>0?[cell(P0([R(" ",{size:2})]),{w:rest,bg:"ECECEC",borders:NB(),margins:{top:0,bottom:0,left:0,right:0}})]:[]),
      ]})]});
    rows.push(new TableRow({children:[
      cell(new Paragraph({spacing:{before:100,after:100},children:[B(sev,{size:22,color:hex})]}),
        {w:LW,bg,borders:{...NB(),bottom:bd(C.border,2)}}),
      cell(new Paragraph({spacing:{before:100,after:100},children:[B(String(cnt),{size:26,color:cnt>0?hex:C.muted})]}),
        {w:CW,bg,borders:{...NB(),bottom:bd(C.border,2)},vAlign:VerticalAlign.CENTER}),
      cell([bar],{w:BW,bg,borders:{...NB(),bottom:bd(C.border,2)},vAlign:VerticalAlign.CENTER,margins:{top:80,bottom:80,left:0,right:0}}),
    ]}));
  });
  return new Table({width:{size:PW,type:WidthType.DXA},columnWidths:[LW,CW,BW],borders:NB(),rows});
}

// ─── PIE/PROPORTION STRIP ────────────────────────────────────────
function buildPieChart(counts) {
  const SEVS=["Critical","High","Medium","Low","Info"];
  const total=SEVS.reduce((a,s)=>a+(counts[s.toLowerCase()]||0),0)||1;
  const stripW=Math.floor(PW*0.46);
  const legW=PW-stripW-160;
  const rawW=SEVS.map(s=>{const c=counts[s.toLowerCase()]||0;return c>0?Math.max(60,Math.round(stripW*c/total)):0;});
  const wSum=rawW.reduce((a,b)=>a+b,0)||1;
  const nW=rawW.map(w=>Math.round(w*stripW/wSum));
  const diff=stripW-nW.reduce((a,b)=>a+b,0);
  for(let i=nW.length-1;i>=0;i--){if(nW[i]>0){nW[i]+=diff;break;}}
  const active=SEVS.map((s,i)=>({sev:s,w:nW[i],cnt:counts[s.toLowerCase()]||0})).filter(x=>x.w>0);
  const stackBar=active.length>0?new Table({
    width:{size:stripW,type:WidthType.DXA},columnWidths:active.map(c=>c.w),borders:NB(),
    rows:[
      new TableRow({children:active.map(c=>cell(
        new Paragraph({alignment:AlignmentType.CENTER,spacing:{before:0,after:0},
          children:[B(`${Math.round(c.cnt/total*100)}%`,{color:C.white,size:17})]}),
        {w:c.w,bg:SEV_HEX(c.sev),borders:NB(),margins:{top:100,bottom:100,left:2,right:2}}
      ))}),
      new TableRow({children:active.map(c=>cell(
        new Paragraph({alignment:AlignmentType.CENTER,spacing:{before:30,after:30},
          children:[B(c.sev,{size:15,color:SEV_HEX(c.sev)})]}),
        {w:c.w,bg:SEV_BG(c.sev),borders:{...NB(),top:bd(C.border,2)},margins:{top:40,bottom:40,left:4,right:4}}
      ))}),
    ]
  }):new Table({width:{size:stripW,type:WidthType.DXA},columnWidths:[stripW],borders:NB(),
    rows:[new TableRow({children:[cell(P0([R("No findings",{color:C.muted})]),{w:stripW,bg:C.bg0})]})]});

  const total_label=P0([B(`Total: ${total} finding${total!==1?"s":""}`,{color:T.accent,size:21})],{spacing:{before:80,after:0}});
  const legRows=SEVS.map(s=>new TableRow({children:[
    cell(P0([R(" ",{size:6})]),{w:260,bg:SEV_HEX(s),borders:NB(),margins:{top:60,bottom:60,left:0,right:0}}),
    cell(P0([B(s,{size:20,color:SEV_HEX(s)})]),{w:1400,borders:NB(),margins:{top:60,bottom:60,left:120,right:60}}),
    cell(P0([B(String(counts[s.toLowerCase()]||0),{size:22,color:SEV_HEX(s)})]),{w:560,borders:NB(),vAlign:VerticalAlign.CENTER}),
    cell(P0([R(`${total>0?Math.round((counts[s.toLowerCase()]||0)/total*100):0}%`,{size:18,color:C.muted})]),{w:560,borders:NB(),vAlign:VerticalAlign.CENTER}),
  ]}));
  const legend=new Table({
    width:{size:legW,type:WidthType.DXA},columnWidths:[260,1400,560,560],borders:NB(),
    rows:[new TableRow({children:[hdrCell("",260),hdrCell("Severity",1400),hdrCell("Count",560),hdrCell("%",560)]}),
      ...legRows]
  });
  return new Table({width:{size:PW,type:WidthType.DXA},columnWidths:[stripW,160,legW],borders:NB(),
    rows:[new TableRow({children:[
      cell([stackBar,total_label],{w:stripW,borders:NB(),vAlign:VerticalAlign.TOP}),
      cell(P0([R(" ")]),{w:160,borders:NB()}),
      cell([legend],{w:legW,borders:NB(),vAlign:VerticalAlign.TOP}),
    ]})]
  });
}

// ─── FINDINGS SUMMARY TABLE ──────────────────────────────────────
function buildSummaryTable(findings) {
  const CW=[640,3200,1240,2700,680,1620];
  const rows=[new TableRow({children:[
    hdrCell("#",CW[0]),hdrCell("Title",CW[1]),hdrCell("Severity",CW[2]),
    hdrCell("Affected Host",CW[3]),hdrCell("CVSS",CW[4]),hdrCell("Retest",CW[5])
  ]})];
  findings.forEach((f,i)=>{
    const sev=normSev(f.severity);
    const hex=SEV_HEX(sev);
    const num=parseFloat(String(f.cvss||"").replace(/[^0-9.]/g,""))||0;
    const vec=(f.cvssVector||"").replace(/`/g,"").trim();
    const url=CVSS_BASE+(vec.includes("AV:")?encodeURIComponent(vec):"");
    const bg=i%2===0?C.bg0:C.white;
    const pill=new Table({width:{size:1100,type:WidthType.DXA},columnWidths:[1100],borders:NB(),
      rows:[new TableRow({children:[
        cell(new Paragraph({alignment:AlignmentType.CENTER,spacing:{before:25,after:25},
          children:[B(sev.toUpperCase(),{size:16,color:C.white})]}),
          {w:1100,bg:hex,borders:NB(),margins:{top:35,bottom:35,left:40,right:40}})
      ]})]
    });
    // Fix Issue 1: clean ID — F-001 not F — 001
    const fid = `F-${String(i+1).padStart(3,"0")}`;
    rows.push(new TableRow({children:[
      cell(P0([B(fid,{size:19,color:T.accent})]),{w:CW[0],bg}),
      cell(P0([R(f.title||"",{size:19})]),{w:CW[1],bg}),
      cell([pill],{w:CW[2],bg,vAlign:VerticalAlign.CENTER}),
      cell(P0([R(f.host||"—",{size:18,color:C.gray})]),{w:CW[3],bg}),
      cell(num>0?new Paragraph({spacing:{before:0,after:0},children:[
        B(`${num}`,{size:20,color:hex}),R("  ",{size:16}),cvssLink("↗",url),
      ]}):P0([R("—")]),{w:CW[4],bg}),
      cell(P0([R("Pending",{size:17,color:C.muted,italics:true})]),{w:CW[5],bg}),
    ]}));
  });
  return new Table({width:{size:PW,type:WidthType.DXA},columnWidths:CW,borders:NB(),rows});
}

// ─── CODE BLOCK (Fix Issue 8: proper monospace shaded box) ───────
function codeBlock(lines, caption) {
  const blocks=[];
  // Header bar
  blocks.push(new Table({width:{size:PW,type:WidthType.DXA},columnWidths:[PW],borders:NB(),
    rows:[new TableRow({children:[
      cell(P0([B("CODE / EVIDENCE",{size:16,color:C.white})]),
        {w:PW,bg:T.accent2,borders:NB(),margins:{top:60,bottom:60,left:200,right:200}})
    ]})]
  }));
  blocks.push(new Table({width:{size:PW,type:WidthType.DXA},columnWidths:[PW],borders:NB(),
    rows:[new TableRow({children:[
      cell(new Paragraph({spacing:{before:60,after:60},
        children:[new TextRun({text:lines.join("\n"),font:"Courier New",size:18,color:"1A3A5A"})]}),
        {w:PW,bg:"F0F5FA",
         borders:{top:noBd(),bottom:bd(T.accent2,4),left:bd(T.accent2,8),right:noBd()},
         margins:{top:100,bottom:100,left:200,right:200}})
    ]})]
  }));
  if(caption){
    blocks.push(new Paragraph({spacing:{before:30,after:100},
      children:[R(`Figure: ${caption}`,{size:17,color:C.muted,italics:true})]}));
  }
  return blocks;
}

// ─── PoC PLACEHOLDER ─────────────────────────────────────────────
let figCounter=1;
function pocBox(figNum, findingTitle) {
  return [
    new Table({width:{size:PW,type:WidthType.DXA},columnWidths:[PW],borders:NB(),
      rows:[new TableRow({children:[
        cell([
          new Paragraph({spacing:{before:60,after:20},children:[
            B(`[Figure ${figNum}: Screenshot / PoC Evidence Placeholder]`,{size:21,color:T.accent2}),
          ]}),
          new Paragraph({spacing:{before:0,after:60},children:[
            R("Replace this placeholder with your screenshot before delivering to client.  ",{size:17,color:C.muted,italics:true}),
            R("Word: Insert › Pictures › This Device",{size:17,color:C.muted}),
          ]}),
        ],{w:PW,bg:C.accentLt,
           borders:{top:bd(T.accent2,6),bottom:bd(C.border,2),left:bd(T.accent2,14),right:bd(C.border,2)},
           margins:{top:120,bottom:120,left:260,right:260}})
      ]})]}
    ),
    new Paragraph({spacing:{before:20,after:80},
      children:[R(`Figure ${figNum}: PoC Evidence — ${findingTitle||"[Replace with finding title]"}`,{size:17,color:C.muted,italics:true})]
    }),
  ];
}

// ─── SECTION BAR ────────────────────────────────────────────────
function secBar(label, bg) {
  return new Table({width:{size:PW,type:WidthType.DXA},columnWidths:[PW],borders:NB(),
    rows:[new TableRow({children:[
      cell(new Paragraph({spacing:{before:60,after:60},children:[B(label,{color:C.white,size:20})]}),
        {w:PW,bg,borders:NB()})
    ]})]
  });
}

// ─── CONTENT BOX ─────────────────────────────────────────────────
function contentBox(text, bg) {
  const paras=[];
  const lines=(text||"").trim().split("\n");
  let inCode=false,codeLines=[];
  let curNumRef=null;
  for(const raw of lines){
    const t=raw.trim();
    if(!t&&!inCode){curNumRef=null;continue;}
    if(t.startsWith("```")){
      if(inCode){if(codeLines.length)codeBlock(codeLines).forEach(b=>paras.push(b));codeLines=[];inCode=false;}
      else inCode=true;
      curNumRef=null;continue;
    }
    if(inCode){codeLines.push(raw);continue;}
    if(t.match(/^>\s*📸/)||t.toLowerCase().includes("screenshot/poc: insert")) continue;
    if(t.startsWith("|")&&t.endsWith("|")){
      const plain=t.replace(/\|/g," | ").replace(/\*\*/g,"").replace(/`/g,"");
      paras.push(P(inline(plain)));curNumRef=null;continue;
    }
    if(/^[-*•]\s/.test(t)){
      paras.push(new Paragraph({numbering:{reference:"bullets",level:0},
        children:inline(t.replace(/^[-*•]\s/,"")),spacing:{before:20,after:20}}));
      curNumRef=null;continue;
    }
    if(/^\d+\.\s/.test(t)){
      if(!curNumRef) curNumRef=freshNum();
      paras.push(new Paragraph({numbering:{reference:curNumRef,level:0},
        children:inline(t.replace(/^\d+\.\s/,"")),spacing:{before:20,after:20}}));continue;
    }
    curNumRef=null;
    if(t.startsWith(">")){
      paras.push(new Paragraph({spacing:{before:40,after:40},indent:{left:360},
        border:{left:{style:BorderStyle.SINGLE,size:8,color:T.accent2}},
        children:inline(t.slice(1).trim(),{color:C.gray,italics:true})}));continue;
    }
    paras.push(P(inline(t)));
  }
  if(inCode&&codeLines.length)codeBlock(codeLines).forEach(b=>paras.push(b));
  return new Table({width:{size:PW,type:WidthType.DXA},columnWidths:[PW],borders:NB(),
    rows:[new TableRow({children:[
      cell(paras.length?paras:[P0([R("—",{color:C.muted})])],
        {w:PW,bg,borders:{...NB(),left:bd(T.accent2,6),bottom:bd(C.border,2)},
         margins:{top:140,bottom:140,left:200,right:200}})
    ]})]
  });
}

// ─── MARKDOWN TABLE ──────────────────────────────────────────────
function parseMdTable(lines){
  const rows=lines.filter(l=>!/^\|[\s\-:|]+\|/.test(l.trim()))
    .map(l=>l.trim().replace(/^\||\\|$/g,"").split("|").map(c=>c.trim()));
  if(!rows.length) return null;
  const cols=Math.max(...rows.map(r=>r.length));
  const cw=Math.floor(PW/cols);
  const cws=Array(cols).fill(cw);cws[cols-1]=PW-cw*(cols-1);
  return new Table({width:{size:PW,type:WidthType.DXA},columnWidths:cws,
    rows:rows.map((row,ri)=>new TableRow({tableHeader:ri===0,children:
      [...row,...Array(Math.max(0,cols-row.length)).fill("")].map((ct,ci)=>{
        const clean=ct.replace(/\*\*/g,"").replace(/`/g,"").trim();
        const isH=ri===0;
        const isSev=["critical","high","medium","low","info"].includes(clean.toLowerCase());
        return cell(P0([R(clean,{bold:isH||isSev,size:20,color:isH?C.white:(isSev?SEV_HEX(clean):C.dark)})]),
          {w:cws[ci],bg:isH?T.accent:(ri%2===0?C.talt:C.white)});
      })
    }))
  });
}

// ─── FINDING EXTRACTOR ──────────────────────────────────────────
// Fix Issue 9: extract ALL findings, not just 2
// Fix Issue 10: complete CVSS vector parsing
function extractFindings(md){
  const findings=[];
  // Match any heading that starts with F-NNN or O-NNN or P-NNN (finding ID patterns)
  const blocks=md.split(/(?=^#{1,4}\s+(?:\*\*)?(?:[A-Z]-?\d{1,3})[:\s—–\-])/mi);
  for(const block of blocks){
    const fl=block.split("\n")[0].trim();
    if(!/^#{1,4}\s+(?:\*\*)?[A-Z]-?\d{1,3}/i.test(fl)) continue;

    const titleRaw = fl.replace(/^#+\s*/,"").replace(/^\*\*|\*\*$/g,"").trim();
    const titleParts = titleRaw.split(/\s*[|—–\-]\s*/);

    let severity="Info", cvssFromTitle="";
    const sevPart = titleParts.find(p=>normSev(p)!=="Info"||/^(critical|high|medium|low|info)$/i.test(p.trim()));
    if(sevPart) severity=normSev(sevPart.trim());
    const cvssPart = titleParts.find(p=>/cvss[\s:]*[\d.]+/i.test(p));
    if(cvssPart){const m=cvssPart.match(/([\d.]+)/);if(m)cvssFromTitle=m[1];}

    // Extract clean title from heading — handle: "F-001 — SQL Injection | Critical | CVSS: 9.8"
    // Step 1: Remove the ID prefix (F-001 or O-001 etc.)
    let cleanTitle = titleRaw.replace(/^[A-Z]-?\d{1,3}\s*[—–|\-]\s*/i, "").trim();
    // Step 2: Remove trailing | Severity | CVSS: X.X or — Severity — CVSS: X.X
    cleanTitle = cleanTitle.replace(/\s*[|—–]\s*(critical|high|medium|low|informational|info)\b.*/i, "").trim();
    cleanTitle = cleanTitle.replace(/\s*[|—–]\s*CVSS:?.*/i, "").trim();
    // Step 3: Remove lone severity word if it's the whole remaining title
    if (/^(critical|high|medium|low|informational|info)$/i.test(cleanTitle)) cleanTitle = "";

    const f={
      title:cleanTitle, severity, cvss:cvssFromTitle,
      cvssVector:"", cve:"", cwe:"", host:"", owasp:"",
      technology:"", rootCause:"", likelihood:"", businessImpact:"",
      remediationDeadline:"", retestStatus:"Pending Retest",
      description:"", evidence:"", impact:"", remediation:""
    };

    const allLines=block.split("\n");
    let endIdx=allLines.length;
    for(let i=2;i<allLines.length;i++){
      const lt=allLines[i].trim();
      // Stop at H1/H2 that marks a new major section (not a sub-section of this finding)
      if(/^#{1,2}\s+/.test(lt)&&!/^#{3,5}\s+/.test(lt)){endIdx=i;break;}
    }
    const bLines=allLines.slice(0,endIdx);
    let sec="description", inCode=false, codeLines=[];

    for(const rawL of bLines.slice(1)){
      const t=rawL.trim();
      if(!t&&!inCode) continue;
      if(t.startsWith("```")){
        if(inCode){if(codeLines.length)f[sec]+=(f[sec]?"\n":"")+["```",...codeLines,"```"].join("\n");codeLines=[];inCode=false;}
        else inCode=true;
        continue;
      }
      if(inCode){codeLines.push(rawL);continue;}
      if(/^#{2,5}/.test(t)){
        const lo=t.toLowerCase();
        if(lo.match(/evidence|proof|poc|screenshot|steps.to.reproduce|reproduce|steps|proof.of/)) {sec="evidence";continue;}
        if(lo.match(/business.impact|impact.analysis|impact/))           {sec="impact";continue;}
        if(lo.match(/remediat|fix|recommend|mitigation|guidance/)){sec="remediation";continue;}
        if(lo.match(/descrip|overview|detail|background/))          {sec="description";continue;}
        continue;
      }
      // Bold-key metadata: **Key:** Value
      const boldKeyMatch = t.match(/^\*\*([^*:]+):\*\*\s*(.+)$/);
      if(boldKeyMatch){
        const [,k,v] = boldKeyMatch;
        const kl = k.toLowerCase().trim();
        const vc = v.replace(/\*\*/g,"").replace(/`/g,"").trim();
        if(kl.includes("severity")&&!kl.includes("sla"))      {f.severity=normSev(vc);continue;}
        if(kl.includes("cvss")&&kl.includes("vector"))        {f.cvssVector=vc;continue;}
        if(kl.includes("cvss"))                                {f.cvss=vc;continue;}
        if(kl.includes("vector"))                              {f.cvssVector=vc;continue;}  // Fix Issue 10
        if(kl.includes("cwe"))                                 {f.cwe=vc;continue;}
        if(kl.includes("cve"))                                 {f.cve=vc;continue;}
        if(kl.includes("owasp"))                               {f.owasp=vc;continue;}
        if(kl.includes("host")||kl.includes("url")||kl.includes("affected")){f.host=f.host||vc;continue;}
        if(kl.includes("technology")||kl.includes("stack"))   {f.technology=vc;continue;}
        if(kl.includes("root cause"))                          {f.rootCause=vc;continue;}
        if(kl.includes("likelihood"))                          {f.likelihood=vc;continue;}
        if(kl.includes("business impact"))                     {f.businessImpact=vc;continue;}
        if(kl.includes("deadline"))                            {f.remediationDeadline=vc;continue;}
        if(kl.includes("retest"))                              {f.retestStatus=vc;continue;}
        continue;
      }
      // Table metadata rows: | Key | Value |
      if(t.startsWith("|")&&t.endsWith("|")){
        if(/^\|[\s\-:|]+\|/.test(t)) continue;
        const m=t.match(/^\|\s*\*?\*?([^|*\-]+)\*?\*?\s*\|\s*(.+?)\s*\|/);
        if(m){
          const[,k,v]=m, kl=k.toLowerCase().trim();
          const vc=v.replace(/\*\*/g,"").replace(/`/g,"").trim();
          if(kl==="field"||kl==="value"||/^[-\s]+$/.test(kl)) continue;
          if(kl.includes("severity")&&!kl.includes("sla"))    {f.severity=normSev(vc);continue;}
          if(kl.includes("cvss")&&kl.includes("vector"))      {f.cvssVector=vc;continue;}
          if(kl.includes("cvss"))                              {f.cvss=vc;continue;}
          if(kl.includes("vector"))                            {f.cvssVector=vc;continue;}  // Fix Issue 10
          if(kl.includes("cwe"))                               {f.cwe=vc;continue;}
          if(kl.includes("cve"))                               {f.cve=f.cve||vc;continue;}
          if(kl.includes("owasp"))                             {f.owasp=vc;continue;}
          if(kl.includes("host")||kl.includes("url")||kl.includes("affected")){f.host=f.host||vc;continue;}
          if(kl.includes("technology"))                        {f.technology=vc;continue;}
          if(kl.includes("root cause"))                        {f.rootCause=vc;continue;}
          if(kl.includes("likelihood"))                        {f.likelihood=vc;continue;}
          if(kl.includes("business impact"))                   {f.businessImpact=vc;continue;}
          if(kl.includes("deadline"))                          {f.remediationDeadline=vc;continue;}
          if(kl.includes("retest"))                            {f.retestStatus=vc;continue;}
          continue;
        }
        continue;
      }
      if(t.match(/^>\s*📸/)||t.toLowerCase().includes("screenshot/poc: insert")) continue;
      f[sec]+=(f[sec]?"\n":"")+rawL.trim();
    }
    if(f.cwe&&f.cve) f.cve=`${f.cve} / ${f.cwe}`;
    else if(f.cwe)   f.cve=f.cwe;
    else if(!f.cve)  f.cve="No CVE — Novel Finding";
    if(cleanTitle) findings.push(f);
  }
  return findings;
}

function countSev(findings){
  const c={critical:0,high:0,medium:0,low:0,info:0};
  for(const f of findings){const k=normSev(f.severity).toLowerCase();if(k in c)c[k]++;else c.info++;}
  return c;
}

// ─── FINDING CARD ────────────────────────────────────────────────
// Fix Issues 1, 3, 4: clean ID, unified metadata table, impact/remediation always shown
function findingCard(f, idx) {
  const sev=normSev(f.severity);
  const hex=SEV_HEX(sev);
  // Fix Issue 1: guaranteed clean ID with no spaces
  const fid=`F-${String(idx).padStart(3,"0")}`;
  const items=[];

  // ── Title bar: themed accent | severity colour ──
  items.push(new Table({width:{size:PW,type:WidthType.DXA},columnWidths:[PW-2200,2200],borders:NB(),
    rows:[new TableRow({children:[
      cell(new Paragraph({spacing:{before:120,after:120},
        children:[B(`${fid}  —  ${f.title||""}`,{size:26,color:C.white})]}),
        {w:PW-2200,bg:T.accent,borders:NB()}),
      cell(new Paragraph({alignment:AlignmentType.CENTER,spacing:{before:120,after:120},
        children:[B(sev.toUpperCase(),{size:22,color:C.white})]}),
        {w:2200,bg:hex,borders:NB()}),
    ]})]}));

  // Fix Issue 3: ONE unified metadata table (6 rows, all fields)
  const vec=(f.cvssVector||"").replace(/`/g,"").trim();
  const num=String(f.cvss||"").replace(/[^0-9.]/g,"");
  const url=CVSS_BASE+(vec.includes("AV:")?encodeURIComponent(vec):"");
  const KW=2300, VW=PW-KW;
  const metaRows=[
    ["Severity",       sev, "CVSS v3.1 Score", num?`${num}  (${sev})`:"—"],
    ["CVSS Vector",    vec||"—", "CVE / CWE", f.cve||"No CVE — Novel Finding"],
    ["OWASP",          f.owasp||"—", "Affected Host", f.host||"—"],
    ["Technology",     f.technology||"—", "Root Cause", f.rootCause||"—"],
    ["Likelihood",     f.likelihood||"—", "Business Impact", f.businessImpact||"—"],
    ["Remediation Deadline", f.remediationDeadline||"—", "Retest Status", f.retestStatus||"Pending Retest"],
  ];
  const metaTblCols=[2300,2540,2300,2940];  // sum=10080
  items.push(new Table({
    width:{size:PW,type:WidthType.DXA},columnWidths:metaTblCols,borders:NB(),
    rows:[
      // Header row
      new TableRow({children:[
        hdrCell("Field",metaTblCols[0]),hdrCell("Value",metaTblCols[1]),
        hdrCell("Field",metaTblCols[2]),hdrCell("Value",metaTblCols[3]),
      ]}),
      ...metaRows.map(([k1,v1,k2,v2],ri)=>{
        const bg=ri%2===0?C.bg0:C.white;
        const isSev1=k1==="Severity";
        const isCvss=k1==="CVSS v3.1 Score"||k1==="Severity";
        return new TableRow({children:[
          cell(P0([B(k1,{size:19,color:T.accent})]),{w:metaTblCols[0],bg,borders:{...NB(),bottom:bd(C.border,2)}}),
          cell(P0(isSev1?[B(v1,{size:20,color:hex})]:num&&k1==="CVSS v3.1 Score"?[B(String(v1).split(" ")[0],{size:22,color:hex}),R("  "),cvssLink("↗ Calc",url)]:[R(v1,{size:19})]),
            {w:metaTblCols[1],bg,borders:{...NB(),bottom:bd(C.border,2)}}),
          cell(P0([B(k2,{size:19,color:T.accent})]),{w:metaTblCols[2],bg,borders:{...NB(),bottom:bd(C.border,2)}}),
          cell(P0([R(v2,{size:19})]),{w:metaTblCols[3],bg,borders:{...NB(),bottom:bd(C.border,2)}}),
        ]});
      }),
    ]
  }));

  items.push(SP(50));

  const pocFig=figCounter++;
  // Fix Issues 4, 8: all sections rendered, code blocks styled
  const SECS=[
    {label:"Description",                key:"description", barBg:T.accent,   contentBg:C.bg0},
    {label:"Evidence and Proof of Concept",key:"evidence",  barBg:T.accent2,  contentBg:C.accentLt, poc:true},
    {label:"Impact Analysis",            key:"impact",      barBg:"7A3500",   contentBg:"FEF6F0"},
    {label:"Remediation Guidance",       key:"remediation", barBg:C.green,    contentBg:C.greenBg},
  ];
  for(const{label,key,barBg,contentBg,poc} of SECS){
    items.push(secBar(label,barBg));
    // Fix Issue 4: always show contentBox even if empty (shows "—" placeholder)
    items.push(contentBox(f[key]||"",contentBg));
    if(poc){items.push(SP(60));pocBox(pocFig,f.title).forEach(el=>items.push(el));}
    items.push(SP(20));
  }
  items.push(SP(180));
  return items;
}

// ─── BODY PARSER ─────────────────────────────────────────────────
function parseBody(md){
  const lines=md.split("\n");
  const out=[];
  let i=0,inCode=false,codeLines=[];
  while(i<lines.length){
    const l=lines[i],t=l.trim();
    if(t.startsWith("```")){
      if(inCode){if(codeLines.length)codeBlock(codeLines).forEach(b=>out.push(b));codeLines=[];inCode=false;}
      else inCode=true;
      i++;continue;
    }
    if(inCode){codeLines.push(l);i++;continue;}
    if(!t||t==="---"){i++;continue;}
    if(t.startsWith("#### ")){out.push(H4(t.slice(5)));i++;continue;}
    if(t.startsWith("### ")){out.push(H3(t.slice(4)));i++;continue;}
    if(t.startsWith("## ")){out.push(H2(t.slice(3)));i++;continue;}
    if(t.startsWith("# ")){out.push(H1(t.slice(2)));i++;continue;}
    if(t.startsWith("|")){
      const tls=[];
      while(i<lines.length&&lines[i].trim().startsWith("|")){tls.push(lines[i]);i++;}
      const tbl=parseMdTable(tls);
      if(tbl){out.push(tbl);out.push(SP(160));}
      continue;
    }
    if(/^[-*•]\s/.test(t)){
      out.push(new Paragraph({numbering:{reference:"bullets",level:0},
        children:inline(t.replace(/^[-*•]\s/,"")),spacing:{before:40,after:40}}));
      i++;continue;
    }
    if(/^\d+\.\s/.test(t)){
      out.push(new Paragraph({numbering:{reference:freshNum(),level:0},
        children:inline(t.replace(/^\d+\.\s/,"")),spacing:{before:40,after:40}}));
      i++;continue;
    }
    if(t.startsWith(">")){
      out.push(new Paragraph({spacing:{before:40,after:40},indent:{left:360},
        border:{left:{style:BorderStyle.SINGLE,size:8,color:T.accent2}},
        children:inline(t.slice(1).trim(),{color:C.gray,italics:true})}));
      i++;continue;
    }
    out.push(P(inline(t)));
    i++;
  }
  return out;
}

// ─── BUILD BODY ──────────────────────────────────────────────────
// Fix Issues 2, 7: NO duplicate findings sections
// The body parser renders preamble prose ONLY (exec summary, engagement overview)
// Then builder appends: Findings Overview (charts) → Detailed Findings → Roadmap
// The AI-generated "Detailed Findings" prose block is STRIPPED before parseBody
function buildBody(md, meta){
  figCounter=1;
  const findings=extractFindings(md);
  const counts=countSev(findings);
  const total=Object.values(counts).reduce((a,b)=>a+b,0);

  // Fix Issue 2: strip everything from "Findings Overview" / "Detailed Findings"
  // onwards so parseBody only renders preamble (exec summary + engagement overview)
  const mdLines=md.split("\n");

  // Find where the "findings" sections begin in the AI output
  // Strip everything from "Findings Overview" / "Detailed Findings" or first finding header onwards
  const stripIdx=mdLines.findIndex(l=>/^#{1,4}\s+(?:(?:\d+[\.\)]\s*)?(?:findings.overview|findings.summar|detailed.finding|vulnerabilit|finding.summar|remediation.roadmap|appendix|overall.risk|key.risk)|(?:[A-Z]-?\d{1,3})\s*[—–|])/i.test(l.trim()));
  const preamble = stripIdx > 0 ? mdLines.slice(0,stripIdx).join("\n") : md;

  return [
    ...parseBody(preamble),

    // Fix Issue 7: single consistent naming
    H1("Findings Overview"),
    H2("Findings Summary Table"),
    SP(80),
    ...(findings.length>0?[buildSummaryTable(findings)]:[P(inline("No structured findings extracted."))]),
    SP(200),
    H2("Severity Distribution"),
    SP(60),
    buildBarChart(counts),
    SP(180),
    H2("Risk Proportion"),
    SP(60),
    buildPieChart(counts),
    SP(60),

    // Fix Issue 2: one Detailed Findings section only (DOCX builder is sole source)
    H1("Detailed Findings"),
    P(inline(`${total} ${total===1?"vulnerability was":"vulnerabilities were"} identified. Each finding includes full metadata, CVSS v3.1 score, CWE, OWASP mapping, evidence, business impact, and remediation guidance.`)),
    SP(120),
    ...(findings.length>0
      ?findings.flatMap((f,i)=>findingCard(f,i+1))
      :[P(inline("No findings extracted. Ensure findings use format: ### F-001 — Title | Severity | CVSS: X.X"))]),

    // Remediation Roadmap
    ...(findings.length>0?[
      H1("Remediation Roadmap"),
      P(inline("Prioritised remediation schedule with time-bound deadlines calculated from the report date.")),
      SP(80),
      new Table({width:{size:PW,type:WidthType.DXA},
        columnWidths:[480,620,2880,1100,1620,1620,1760],
        rows:[
          new TableRow({children:[
            hdrCell("#",480),hdrCell("ID",620),hdrCell("Finding",2880),hdrCell("Severity",1100),
            hdrCell("SLA",1620),hdrCell("Owner",1620),hdrCell("Status",1760)
          ]}),
          ...findings.map((f,i)=>{
            const sev=normSev(f.severity);
            const hex=SEV_HEX(sev);
            const bg=i%2===0?C.bg0:C.white;
            const fid=`F-${String(i+1).padStart(3,"0")}`;
            return new TableRow({children:[
              cell(P0([R(String(i+1),{size:19})]),{w:480,bg}),
              cell(P0([B(fid,{size:19,color:T.accent})]),{w:620,bg}),
              cell(P0([R(f.title||"",{size:19})]),{w:2880,bg}),
              cell(P0([B(sev,{size:19,color:hex})]),{w:1100,bg}),
              cell(P0([R(SEV_SLA(sev),{size:18})]),{w:1620,bg}),
              cell(P0([R("Security Team",{size:18})]),{w:1620,bg}),
              cell(P0([R("Open",{size:18,color:C.muted,italics:true})]),{w:1760,bg}),
            ]});
          }),
        ]
      }),
      SP(160),
    ]:[]),

    // ── Appendix ──
    H1("Appendix"),
    H2("A. Tools and Technologies Used"),
    SP(60),
    new Table({width:{size:PW,type:WidthType.DXA},
      columnWidths:[2200,1400,2000,4480],
      rows:[
        new TableRow({children:[hdrCell("Tool",2200),hdrCell("Version",1400),hdrCell("Category",2000),hdrCell("Purpose",4480)]}),
        ...([
          ["Burp Suite Pro","2024.x","Web Proxy","Manual web application testing, intercept and replay"],
          ["Nmap","7.94","Network Scanner","Port scanning, service detection, OS fingerprinting"],
          ["Metasploit Framework","6.x","Exploitation","Exploit development, post-exploitation, pivoting"],
          ["SQLMap","1.8","Web Exploitation","Automated SQL injection detection and exploitation"],
          ["Nuclei","3.x","Vulnerability Scanner","Template-based scanning across thousands of CVEs"],
          ["OWASP ZAP","2.14","Web Scanner","Automated DAST scanning, API fuzzing"],
          ["Gobuster / ffuf","3.6 / 2.x","Enumeration","Directory brute-forcing, vhost and parameter discovery"],
          ["Impacket","0.12","Network Exploitation","SMB, WMI, Kerberos, NTLM relay attacks"],
          ["BloodHound","4.x","AD Analysis","Active Directory attack path and privilege escalation mapping"],
          ["Hashcat","6.x","Password Cracking","Offline password hash cracking"],
          ["Nessus / OpenVAS","10.x","Vuln Scanner","Authenticated and unauthenticated vulnerability scanning"],
          ["Nikto","2.x","Web Scanner","Web server misconfiguration and vulnerability detection"],
          ["WireShark","4.x","Packet Analysis","Network traffic capture and protocol analysis"],
        ]).map(([tool,ver,cat,purpose],i)=>new TableRow({children:[
          cell(P0([B(tool,{size:19,color:T.accent})]),{w:2200,bg:i%2===0?C.bg0:C.white,borders:{...NB(),bottom:bd(C.border,2)}}),
          cell(P0([R(ver,{size:18,color:C.muted})]),{w:1400,bg:i%2===0?C.bg0:C.white,borders:{...NB(),bottom:bd(C.border,2)}}),
          cell(P0([R(cat,{size:18})]),{w:2000,bg:i%2===0?C.bg0:C.white,borders:{...NB(),bottom:bd(C.border,2)}}),
          cell(P0([R(purpose,{size:18})]),{w:4480,bg:i%2===0?C.bg0:C.white,borders:{...NB(),bottom:bd(C.border,2)}}),
        ]}))
      ]
    }),
    SP(200),
    H2("B. Retest Tracking"),
    SP(60),
    ...(findings.length>0?[
      new Table({width:{size:PW,type:WidthType.DXA},
        columnWidths:[640,2800,1100,1300,1400,1300,1540],
        rows:[
          new TableRow({children:[
            hdrCell("ID",640),hdrCell("Finding",2800),hdrCell("Severity",1100),
            hdrCell("Fix Applied",1300),hdrCell("Retest Date",1400),
            hdrCell("Result",1300),hdrCell("Verified By",1540)
          ]}),
          ...findings.map((f,i)=>{
            const sev=normSev(f.severity);
            const hex=SEV_HEX(sev);
            const bg=i%2===0?C.bg0:C.white;
            const fid=`F-${String(i+1).padStart(3,"0")}`;
            return new TableRow({children:[
              cell(P0([B(fid,{size:18,color:T.accent})]),{w:640,bg}),
              cell(P0([R(f.title||"",{size:18})]),{w:2800,bg}),
              cell(P0([B(sev,{size:18,color:hex})]),{w:1100,bg}),
              cell(P0([R("Pending",{size:17,color:C.muted,italics:true})]),{w:1300,bg}),
              cell(P0([R("TBD",{size:17,color:C.muted})]),{w:1400,bg}),
              cell(P0([R("Pending",{size:17,color:C.muted,italics:true})]),{w:1300,bg}),
              cell(P0([R("TBD",{size:17,color:C.muted})]),{w:1540,bg}),
            ]});
          })
        ]
      }),
    ]:[P(inline("No findings to retest."))]),
    SP(200),
    H2("C. Glossary"),
    SP(60),
    new Table({width:{size:PW,type:WidthType.DXA},
      columnWidths:[2000,8080],
      rows:[
        new TableRow({children:[hdrCell("Term",2000),hdrCell("Definition",8080)]}),
        ...([
          ["CVSS","Common Vulnerability Scoring System v3.1 — industry standard for rating vulnerability severity on a 0–10 scale."],
          ["CWE","Common Weakness Enumeration — a community-developed list of software and hardware weakness types."],
          ["CVE","Common Vulnerabilities and Exposures — standardised identifiers for publicly known cybersecurity vulnerabilities."],
          ["OWASP","Open Web Application Security Project — non-profit foundation producing free resources on web application security."],
          ["PTES","Penetration Testing Execution Standard — defines the baseline for penetration test execution and reporting."],
          ["NIST","National Institute of Standards and Technology — US federal agency producing cybersecurity frameworks and guidelines."],
          ["PoC","Proof of Concept — working demonstration that a vulnerability is exploitable."],
          ["SLA","Service Level Agreement — agreed remediation deadline based on finding severity."],
          ["IOC","Indicator of Compromise — forensic data indicating potential intrusion or malicious activity."],
          ["TTP","Tactics, Techniques, and Procedures — description of adversary behaviour aligned to MITRE ATT&CK."],
          ["MITRE ATT&CK","Adversarial Tactics, Techniques, and Common Knowledge — globally recognised knowledge base of adversary techniques."],
        ]).map(([term,def],i)=>new TableRow({children:[
          cell(P0([B(term,{size:19,color:T.accent})]),{w:2000,bg:i%2===0?C.bg0:C.white,borders:{...NB(),bottom:bd(C.border,2)}}),
          cell(P0([R(def,{size:19})]),{w:8080,bg:i%2===0?C.bg0:C.white,borders:{...NB(),bottom:bd(C.border,2)}}),
        ]}))
      ]
    }),
    SP(160),
  ];
}

// ─── HEADER / FOOTER ─────────────────────────────────────────────
function makeHeader(meta){
  const rtype=(meta.report_type||"pentest").toLowerCase();
  const typeStr=rtype==="redteam"?"Red Team Report":rtype==="phishing"?"Phishing Assessment":"Penetration Test Report";
  return new Header({children:[
    new Paragraph({
      spacing:{before:0,after:80},
      border:{bottom:{style:BorderStyle.SINGLE,size:4,color:T.accent}},
      tabStops:[{type:TabStopType.RIGHT,position:PW}],
      children:[
        B(`${meta.client||"Security Assessment"}  ·  ${typeStr}`,{size:17,color:T.accent}),
        new TextRun({text:"\t",font:"Calibri"}),
        R("CONFIDENTIAL",{size:15,color:C.muted,italics:true}),
      ]
    }),
  ]});
}

function makeFooter(meta){
  return new Footer({children:[
    new Paragraph({
      spacing:{before:0,after:60},
      border:{top:{style:BorderStyle.SINGLE,size:8,color:T.accent}},
      tabStops:[
        {type:TabStopType.CENTER,position:Math.floor(PW/2)},
        {type:TabStopType.RIGHT, position:PW},
      ],
      children:[
        R(meta.date||"",{size:15,color:C.muted}),
        R("  ·  CONFIDENTIAL",{size:13,color:C.muted,italics:true}),
        new TextRun({text:"\t",font:"Calibri"}),
        R("Page ",{size:15,color:C.muted}),
        new TextRun({children:[PageNumber.CURRENT],font:"Calibri",size:15,color:C.muted}),
        R(" of ",{size:15,color:C.muted}),
        new TextRun({children:[PageNumber.TOTAL_PAGES],font:"Calibri",size:15,color:C.muted}),
        new TextRun({text:"\t",font:"Calibri"}),
        R("Mahendra Purbia",{size:14,color:C.muted,italics:true}),
      ]
    }),
  ]});
}

// ─── ASSEMBLE ────────────────────────────────────────────────────
const coverChildren = buildCoverPage1(meta, COMP, TEST);
const coverPage2    = buildCoverPage2(meta);
const bodyChildren  = [
  ...buildDocControl(meta),
  ...buildTOC(RTYPE),
  ...buildBody(MD, meta),
];

const STYLES={
  default:{document:{run:{font:"Calibri",size:22,color:C.dark}}},
  paragraphStyles:[
    {id:"Heading1",name:"Heading 1",basedOn:"Normal",next:"Normal",quickFormat:true,
      run:{size:40,bold:true,font:"Calibri",color:T.accent},
      paragraph:{spacing:{before:0,after:240},outlineLevel:0}},
    {id:"Heading2",name:"Heading 2",basedOn:"Normal",next:"Normal",quickFormat:true,
      run:{size:30,bold:true,font:"Calibri",color:T.accent2},
      paragraph:{spacing:{before:400,after:140},outlineLevel:1}},
    {id:"Heading3",name:"Heading 3",basedOn:"Normal",next:"Normal",quickFormat:true,
      run:{size:26,bold:true,color:T.accent},
      paragraph:{spacing:{before:280,after:100},outlineLevel:2}},
    {id:"Heading4",name:"Heading 4",basedOn:"Normal",next:"Normal",quickFormat:true,
      run:{size:22,bold:true,color:C.gray},
      paragraph:{spacing:{before:180,after:60},outlineLevel:3}},
  ]
};

const NUMBERING={config:[
  {reference:"bullets",levels:[{level:0,format:LevelFormat.BULLET,text:"•",
    alignment:AlignmentType.LEFT,
    style:{paragraph:{indent:{left:720,hanging:360}},run:{font:"Calibri",size:22}}}]},
  {reference:"olist0",levels:[{level:0,format:LevelFormat.DECIMAL,text:"%1.",
    alignment:AlignmentType.LEFT,
    style:{paragraph:{indent:{left:720,hanging:360}},run:{font:"Calibri",size:22}}}]},
  ...Array.from({length:80},(_,i)=>({
    reference:`olist${i+1}`,
    levels:[{level:0,format:LevelFormat.DECIMAL,text:"%1.",
      alignment:AlignmentType.LEFT,
      style:{paragraph:{indent:{left:720,hanging:360}},run:{font:"Calibri",size:22}}}]
  }))
]};

const doc=new Document({
  numbering:NUMBERING,
  styles:STYLES,
  sections:[
    // Section 1: Cover page — zero margins, confidential bar lives in footer (always at page bottom)
    {
      properties:{type:"nextPage",page:{
        size:{width:12240,height:15840},
        margin:{top:0,bottom:520,left:0,right:0},
      }},
      headers:{default:new Header({children:[P0([R("")])]})},
      footers:{default:buildCoverFooter(meta, TEST)},
      children:coverChildren,
    },
    // Section 2: Report information page
    {
      properties:{type:"nextPage",page:{
        size:{width:12240,height:15840},
        margin:{top:720,bottom:720,left:1080,right:1080},
      }},
      headers:{default:new Header({children:[P0([R("")])]})},
      footers:{default:new Footer({children:[P0([R("")])]})},
      children:coverPage2,
    },
    // Section 3: Body — running header/footer
    {
      properties:{type:"nextPage",page:{
        size:{width:12240,height:15840},
        margin:{top:720,bottom:720,left:1080,right:1080},
      }},
      headers:{default:makeHeader(meta)},
      footers:{default:makeFooter(meta)},
      children:bodyChildren,
    },
  ]
});

Packer.toBuffer(doc).then(buf=>{
  fs.writeFileSync(outputFile,buf);
  console.log("OK:"+outputFile);
}).catch(e=>{
  console.error("ERR:"+e.message);
  process.exit(1);
});
