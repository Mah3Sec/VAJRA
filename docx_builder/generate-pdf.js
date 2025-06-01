"use strict";
/**
 * VAJRA — generate-pdf.js
 * Pure Node.js PDF generator — no external binaries required.
 * Called by app.py as: node generate-pdf.js input.json output.pdf
 *
 * Dependencies (run once in docx_builder/):
 *   npm install pdfkit markdown-it
 *
 * Uses pdfkit for PDF rendering and markdown-it to parse markdown.
 * Produces a professional A4 report with cover page, styled headings,
 * tables, code blocks, and finding cards.
 */

const fs   = require("fs");
const path = require("path");

const inputFile  = process.argv[2];
const outputFile = process.argv[3];

if (!inputFile || !outputFile) {
  console.error("Usage: node generate-pdf.js input.json output.pdf");
  process.exit(1);
}

// ── Load input ───────────────────────────────────────────────────────────────
let raw;
try { raw = JSON.parse(fs.readFileSync(inputFile, "utf8")); }
catch(e) { console.error("ERR: Cannot read input: " + e.message); process.exit(1); }

const MD   = String(raw.content || "");
const meta = raw.meta || {};

// ── Load dependencies ────────────────────────────────────────────────────────
let PDFDocument, markdownit;
try {
  PDFDocument = require("pdfkit");
  markdownit  = require("markdown-it");
} catch(e) {
  console.error("ERR: Missing dependencies. Run: npm install pdfkit markdown-it");
  console.error(e.message);
  process.exit(2);
}

// ── Theme ────────────────────────────────────────────────────────────────────
const RTYPE = (meta.report_type || "pentest").toLowerCase();
const THEME = {
  pentest:  { accent: "#1B2A4A", accent2: "#2E75B6", label: "Penetration Test Report" },
  redteam:  { accent: "#8B0000", accent2: "#C0392B", label: "Red Team Engagement Report" },
  phishing: { accent: "#7A4800", accent2: "#E67E22", label: "Phishing Campaign Assessment" },
};
const T = THEME[RTYPE] || THEME.pentest;

// Severity colours
const SEV_COLOR = {
  critical:      "#8B0000",
  high:          "#9B3A00",
  medium:        "#7A5900",
  low:           "#1E5C2E",
  informational: "#1A3E6E",
  info:          "#1A3E6E",
};

// ── PDF Setup ────────────────────────────────────────────────────────────────
const doc = new PDFDocument({
  size: "A4",
  margins: { top: 55, bottom: 55, left: 60, right: 60 },
  info: {
    Title:   meta.title || "Security Assessment Report",
    Author:  meta.tester || "Security Team",
    Subject: T.label,
    Creator: "VAJRA Report Generator",
  },
  autoFirstPage: false,
});

const stream = fs.createWriteStream(outputFile);
doc.pipe(stream);

// ── Helpers ──────────────────────────────────────────────────────────────────
const W = 595 - 120;  // A4 width minus margins

function hexToRgb(hex) {
  const r = parseInt(hex.slice(1,3),16);
  const g = parseInt(hex.slice(3,5),16);
  const b = parseInt(hex.slice(5,7),16);
  return [r,g,b];
}

function setFill(hex)   { doc.fillColor(hexToRgb(hex)); }
function setStroke(hex) { doc.strokeColor(hexToRgb(hex)); }

function hBar(color, h=3) {
  setFill(color);
  doc.rect(doc.page.margins.left, doc.y, W, h).fill();
  doc.moveDown(0.3);
}

function ensureSpace(needed) {
  const avail = doc.page.height - doc.page.margins.bottom - doc.y;
  if (avail < needed) doc.addPage();
}

function textLine(text, opts={}) {
  const defaults = { font:"Helvetica", size:10, color:"#1a1a1a", continued:false };
  const o = {...defaults, ...opts};
  doc.font(o.bold ? "Helvetica-Bold" : (o.italic ? "Helvetica-Oblique" : o.font));
  doc.fontSize(o.size);
  setFill(o.color);
  if (o.continued) {
    doc.text(text, { continued: true, ...o });
  } else {
    doc.text(text, doc.page.margins.left, doc.y, { width: W, ...o });
  }
}

function sectionBar(label, color) {
  ensureSpace(30);
  doc.moveDown(0.4);
  setFill(color);
  doc.rect(doc.page.margins.left, doc.y, W, 20).fill();
  doc.font("Helvetica-Bold").fontSize(9).fillColor("white");
  doc.text(label.toUpperCase(), doc.page.margins.left + 8, doc.y - 15, { width: W - 16 });
  doc.moveDown(0.5);
  setFill("#1a1a1a");
}

// ── Cover Page ───────────────────────────────────────────────────────────────
doc.addPage();

// Top accent bar
setFill(T.accent);
doc.rect(0, 0, 595, 8).fill();

// Center content vertically ~40% down
const coverY = 180;
doc.y = coverY;

// Report type label
doc.font("Helvetica").fontSize(9).fillColor("#999999");
doc.text(T.label.toUpperCase(), doc.page.margins.left, doc.y,
  { width: W, align: "center", characterSpacing: 3 });
doc.moveDown(1.2);

// Title
const titleText = meta.title || "Security Assessment Report";
doc.font("Helvetica-Bold").fontSize(22).fillColor(hexToRgb(T.accent));
doc.text(titleText, doc.page.margins.left, doc.y, { width: W, align: "center" });
doc.moveDown(0.5);

// Divider
hBar(T.accent2, 1);
doc.moveDown(1);

// Meta block
const metaItems = [];
if (meta.client)       metaItems.push(["Client",     meta.client]);
if (meta.tester)       metaItems.push(["Prepared By", meta.tester]);
if (meta.date)         metaItems.push(["Date",        meta.date]);
if (meta.report_type)  metaItems.push(["Report Type", T.label]);
metaItems.push(["Classification", "CONFIDENTIAL — NOT FOR DISTRIBUTION"]);

for (const [k, v] of metaItems) {
  const lineY = doc.y;
  doc.font("Helvetica-Bold").fontSize(9).fillColor(hexToRgb(T.accent));
  doc.text(k + ":", doc.page.margins.left, lineY, { width: 110, continued: false });
  doc.font("Helvetica").fontSize(9).fillColor("#333333");
  doc.text(v, doc.page.margins.left + 120, lineY, { width: W - 120 });
  doc.moveDown(0.4);
}

// Bottom accent bar
setFill(T.accent);
doc.rect(0, 595.28*1.414 - 8, 595, 8).fill();  // A4 height ≈ 841.89

// ── Body Pages ───────────────────────────────────────────────────────────────
doc.addPage();

// Running header
doc.on("pageAdded", () => {
  const hY = 18;
  doc.font("Helvetica").fontSize(7.5).fillColor("#888888");
  doc.text(meta.client || "Security Assessment", doc.page.margins.left, hY, { width: W/2 });
  doc.text(meta.date || "", doc.page.margins.left + W/2, hY, { width: W/2, align: "right" });
  setFill(T.accent);
  doc.rect(doc.page.margins.left, hY + 10, W, 0.5).fill();
  // Reset color
  setFill("#1a1a1a");
});

// Running footer
const addFooter = () => {
  const fY = doc.page.height - 35;
  setFill(T.accent);
  doc.rect(doc.page.margins.left, fY, W, 0.5).fill();
  doc.font("Helvetica").fontSize(7.5).fillColor("#888888");
  doc.text("CONFIDENTIAL — NOT FOR DISTRIBUTION", doc.page.margins.left, fY + 5,
    { width: W, align: "center" });
};

// ── Markdown Parser ──────────────────────────────────────────────────────────
const mdi = markdownit({ html: false, linkify: false, typographer: false });

function stripMd(text) {
  return text.replace(/\*\*(.+?)\*\*/g, "$1")
             .replace(/\*(.+?)\*/g, "$1")
             .replace(/`(.+?)`/g, "$1")
             .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
             .trim();
}

function normSev(s) {
  const l = (s||"").toLowerCase().trim();
  if (l.includes("critical")) return "critical";
  if (l.includes("high"))     return "high";
  if (l.includes("medium"))   return "medium";
  if (l.includes("low"))      return "low";
  return "info";
}

function renderInline(text) {
  // Render bold/code inline within a paragraph
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  const chunks = [];
  for (const p of parts) {
    if (p.startsWith("**") && p.endsWith("**")) {
      chunks.push({ text: p.slice(2,-2), bold: true });
    } else if (p.startsWith("`") && p.endsWith("`")) {
      chunks.push({ text: p.slice(1,-1), code: true });
    } else if (p) {
      chunks.push({ text: p });
    }
  }
  return chunks;
}

function writeParagraph(text, opts={}) {
  if (!text.trim()) return;
  const chunks = renderInline(text);
  const startX = doc.page.margins.left;
  let x = startX;
  const lineH = (opts.size || 10) * 1.4;
  ensureSpace(lineH * 2);

  for (let i = 0; i < chunks.length; i++) {
    const c = chunks[i];
    const isLast = i === chunks.length - 1;
    if (c.code) {
      doc.font("Courier").fontSize((opts.size||10) - 0.5).fillColor("#2E5090");
    } else if (c.bold) {
      doc.font("Helvetica-Bold").fontSize(opts.size||10).fillColor(opts.color || "#111");
    } else {
      doc.font(opts.bold ? "Helvetica-Bold" : "Helvetica")
         .fontSize(opts.size||10).fillColor(opts.color || "#333");
    }
    doc.text(c.text, { continued: !isLast, width: W });
  }
  if (!opts.noMove) doc.moveDown(0.3);
}

function renderTable(rows) {
  if (!rows || rows.length === 0) return;
  ensureSpace(60);

  const colCount = rows[0].length;
  const colW = W / colCount;

  for (let ri = 0; ri < rows.length; ri++) {
    const row = rows[ri];
    const isHeader = ri === 0;
    const rowH = 18;

    ensureSpace(rowH + 4);
    const rowY = doc.y;

    // Row background
    if (isHeader) {
      setFill(T.accent);
      doc.rect(doc.page.margins.left, rowY, W, rowH).fill();
    } else if (ri % 2 === 0) {
      setFill("#F7F9FC");
      doc.rect(doc.page.margins.left, rowY, W, rowH).fill();
    }

    // Row border
    setStroke("#C8D4E0");
    doc.rect(doc.page.margins.left, rowY, W, rowH).stroke();

    // Cells
    for (let ci = 0; ci < row.length; ci++) {
      const cellX = doc.page.margins.left + ci * colW;
      const cellText = stripMd(String(row[ci] || "")).slice(0, 120);

      // Severity colouring in data cells
      let textColor = isHeader ? "white" : "#1a1a1a";
      if (!isHeader) {
        const sevKey = normSev(cellText);
        if (SEV_COLOR[sevKey] && /^(critical|high|medium|low|info)/i.test(cellText)) {
          textColor = SEV_COLOR[sevKey];
        }
      }

      doc.font(isHeader ? "Helvetica-Bold" : "Helvetica")
         .fontSize(isHeader ? 8.5 : 9)
         .fillColor(textColor === "white" ? [255,255,255] : hexToRgb(textColor));
      doc.text(cellText, cellX + 4, rowY + 5, {
        width: colW - 8,
        height: rowH - 6,
        lineBreak: false,
        ellipsis: true,
      });
    }
    doc.y = rowY + rowH;
  }
  doc.moveDown(0.6);
  setFill("#1a1a1a");
}

function renderCodeBlock(lines) {
  const text = lines.join("\n").slice(0, 2000);
  ensureSpace(40);
  const blockH = Math.min(lines.length * 11 + 16, 200);

  // Background
  setFill("#F0F5FA");
  doc.rect(doc.page.margins.left, doc.y, W, blockH).fill();
  // Left accent
  setFill(T.accent);
  doc.rect(doc.page.margins.left, doc.y, 3, blockH).fill();

  doc.font("Courier").fontSize(8).fillColor("#1a1a1a");
  doc.text(text, doc.page.margins.left + 8, doc.y + 6, {
    width: W - 16, height: blockH - 10,
    lineBreak: true, ellipsis: true,
  });
  doc.y += blockH + 4;
  doc.moveDown(0.3);
  setFill("#1a1a1a");
}

// ── Main Renderer ────────────────────────────────────────────────────────────
function renderMarkdown(md) {
  const lines = md.split("\n");
  let i = 0;
  let inCode = false;
  let codeLines = [];
  let tableRows = [];
  let inTable = false;

  while (i < lines.length) {
    const raw = lines[i];
    const t   = raw.trim();

    // Code block
    if (t.startsWith("```")) {
      if (inCode) {
        renderCodeBlock(codeLines);
        codeLines = [];
        inCode = false;
      } else {
        inCode = true;
      }
      i++; continue;
    }
    if (inCode) { codeLines.push(raw); i++; continue; }

    // Flush table if we hit a non-table line
    if (inTable && !t.startsWith("|")) {
      renderTable(tableRows);
      tableRows = [];
      inTable = false;
    }

    // Table row
    if (t.startsWith("|")) {
      if (/^\|[\s\-:|]+\|/.test(t)) { i++; continue; } // separator row
      const cells = t.split("|").slice(1,-1).map(c => c.trim());
      tableRows.push(cells);
      inTable = true;
      i++; continue;
    }

    // Headings
    if (t.startsWith("# ") && !t.startsWith("## ")) {
      // H1 — new section
      if (doc.y > 100) ensureSpace(50);
      doc.moveDown(0.8);
      hBar(T.accent, 2);
      doc.font("Helvetica-Bold").fontSize(16).fillColor(hexToRgb(T.accent));
      doc.text(stripMd(t.slice(2)), doc.page.margins.left, doc.y, { width: W });
      doc.moveDown(0.5);
      i++; continue;
    }
    if (t.startsWith("## ")) {
      ensureSpace(40);
      doc.moveDown(0.5);
      doc.font("Helvetica-Bold").fontSize(13).fillColor(hexToRgb(T.accent2));
      doc.text(stripMd(t.slice(3)), doc.page.margins.left, doc.y, { width: W });
      setFill("#C8D4E0");
      doc.rect(doc.page.margins.left, doc.y + 1, W, 0.5).fill();
      doc.moveDown(0.5);
      i++; continue;
    }
    if (t.startsWith("### ")) {
      ensureSpace(30);
      // Check if it's a finding header: ### F-001 — Title | Severity | CVSS: X
      const findingMatch = t.match(/^###\s+([A-Z]-\d{3})\s*[—–-]\s*(.+?)(?:\s*\|\s*(critical|high|medium|low|info))?(?:\s*\|\s*CVSS:\s*([\d.]+))?$/i);
      if (findingMatch) {
        const [, fid, ftitle, fsev, fcvss] = findingMatch;
        const sev = normSev(fsev || "");
        const sevColor = SEV_COLOR[sev] || "#333";
        const cleanTitle = stripMd(ftitle.replace(/\s*\|.*$/, "").trim());

        doc.moveDown(0.4);
        // Finding title bar
        setFill(T.accent);
        doc.rect(doc.page.margins.left, doc.y, W, 24).fill();
        doc.font("Helvetica-Bold").fontSize(10).fillColor([255,255,255]);
        doc.text(`${fid}  —  ${cleanTitle}`, doc.page.margins.left + 8, doc.y - 18, { width: W - 120 });
        if (fsev) {
          const sevLabel = (fsev||"").trim().toUpperCase();
          doc.font("Helvetica-Bold").fontSize(9).fillColor([255,255,255]);
          doc.text(sevLabel, doc.page.margins.left + W - 100, doc.y - 18, { width: 90, align: "right" });
        }
        doc.y += 8;
        doc.moveDown(0.3);
      } else {
        doc.font("Helvetica-Bold").fontSize(11).fillColor(hexToRgb(T.accent2));
        doc.text(stripMd(t.slice(4)), doc.page.margins.left, doc.y, { width: W });
        doc.moveDown(0.3);
      }
      i++; continue;
    }
    if (t.startsWith("#### ")) {
      ensureSpace(20);
      // Section sub-headings inside findings (Description, Evidence, etc.)
      const label = stripMd(t.slice(5));
      sectionBar(label, T.accent2);
      i++; continue;
    }
    if (t.startsWith("##### ")) {
      ensureSpace(16);
      doc.font("Helvetica-Bold").fontSize(9.5).fillColor("#333");
      doc.text(stripMd(t.slice(6)), doc.page.margins.left, doc.y, { width: W });
      doc.moveDown(0.2);
      i++; continue;
    }

    // Horizontal rule
    if (/^---+$/.test(t)) {
      setFill("#DDE8F0");
      doc.rect(doc.page.margins.left, doc.y, W, 0.5).fill();
      doc.moveDown(0.4);
      i++; continue;
    }

    // Bold key-value lines: **Key:** Value (common in finding metadata)
    const kvMatch = t.match(/^\*\*([^*:]+):\*\*\s*(.*)$/);
    if (kvMatch) {
      ensureSpace(14);
      const [, k, v] = kvMatch;
      const lineY = doc.y;
      doc.font("Helvetica-Bold").fontSize(9).fillColor(hexToRgb(T.accent));
      doc.text(k + ":", doc.page.margins.left, lineY, { width: 130, continued: false });

      // Colour severity values
      let vColor = "#333";
      const sevKey = normSev(v);
      if (k.toLowerCase().includes("severity") && SEV_COLOR[sevKey]) vColor = SEV_COLOR[sevKey];

      doc.font("Helvetica").fontSize(9).fillColor(hexToRgb(vColor));
      doc.text(stripMd(v), doc.page.margins.left + 135, lineY, { width: W - 135 });
      doc.moveDown(0.25);
      i++; continue;
    }

    // Bullet / list item
    if (/^[-*•]\s/.test(t)) {
      ensureSpace(14);
      const text = stripMd(t.replace(/^[-*•]\s+/, ""));
      doc.font("Helvetica").fontSize(9.5).fillColor("#333");
      doc.text("•  " + text, doc.page.margins.left + 8, doc.y, { width: W - 8 });
      doc.moveDown(0.25);
      i++; continue;
    }

    // Numbered list
    const numMatch = t.match(/^(\d+)[.)]\s+(.+)$/);
    if (numMatch) {
      ensureSpace(14);
      const [, num, text] = numMatch;
      doc.font("Helvetica").fontSize(9.5).fillColor("#333");
      doc.text(`${num}.  ${stripMd(text)}`, doc.page.margins.left + 8, doc.y, { width: W - 8 });
      doc.moveDown(0.25);
      i++; continue;
    }

    // Blockquote (PoC screenshot placeholder)
    if (t.startsWith(">")) {
      const qtext = t.replace(/^>\s*/, "");
      if (qtext.includes("📸") || qtext.toLowerCase().includes("screenshot")) {
        ensureSpace(30);
        setFill("#F7F9FC");
        doc.rect(doc.page.margins.left, doc.y, W, 24).fill();
        setStroke("#C8D4E0");
        doc.rect(doc.page.margins.left, doc.y, W, 24).stroke();
        doc.font("Helvetica").fontSize(8.5).fillColor("#888");
        doc.text("📸  " + stripMd(qtext), doc.page.margins.left + 8, doc.y + 7, { width: W - 16 });
        doc.y += 28;
        doc.moveDown(0.2);
      } else {
        doc.font("Helvetica-Oblique").fontSize(9.5).fillColor("#666");
        setFill("#C8D4E0");
        doc.rect(doc.page.margins.left, doc.y, 2.5, 14).fill();
        doc.text(stripMd(qtext), doc.page.margins.left + 10, doc.y - 12, { width: W - 10 });
        doc.moveDown(0.3);
      }
      setFill("#1a1a1a");
      i++; continue;
    }

    // Empty line
    if (!t) { doc.moveDown(0.25); i++; continue; }

    // Default paragraph
    ensureSpace(16);
    writeParagraph(t, { size: 10 });
    i++;
  }

  // Flush any remaining table or code
  if (inTable && tableRows.length) renderTable(tableRows);
  if (inCode && codeLines.length)  renderCodeBlock(codeLines);
}

// ── Render ───────────────────────────────────────────────────────────────────
try {
  renderMarkdown(MD);
} catch(e) {
  console.error("ERR: Render failed: " + e.message);
  process.exit(1);
}

// ── Finalise ─────────────────────────────────────────────────────────────────
doc.end();
stream.on("finish", () => {
  console.log("OK:" + outputFile);
});
stream.on("error", (e) => {
  console.error("ERR: Write failed: " + e.message);
  process.exit(1);
});
