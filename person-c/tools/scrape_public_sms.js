"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { chromium } = require("playwright");

const ROOT = path.resolve(__dirname, "..");
const DATA_DIR = path.join(ROOT, "data");
const SOURCES = {
  phishing: "https://raw.githubusercontent.com/wspr-ncsu/sms-phishing/main/phishing_messages.csv",
  legacy: "https://raw.githubusercontent.com/nitish-niraj/sms-spam/main/data/raw/sms%2Bspam%2Bcollection/SMSSpamCollection",
};

function parseCsv(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted && ch === '"' && text[i + 1] === '"') { field += '"'; i += 1; continue; }
    if (ch === '"') { quoted = !quoted; continue; }
    if (!quoted && ch === ",") { row.push(field); field = ""; continue; }
    if (!quoted && (ch === "\n" || ch === "\r")) {
      if (ch === "\r" && text[i + 1] === "\n") i += 1;
      row.push(field); field = "";
      if (row.some((value) => value.length > 0)) rows.push(row);
      row = [];
      continue;
    }
    field += ch;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

function clean(text) {
  return text
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/g, "")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[EMAIL]")
    .replace(/\+?\d[\d\s().-]{6,}\d/g, "[PHONE]")
    .replace(/\s+/g, " ")
    .trim();
}

function template(text) {
  return clean(text)
    .toLowerCase()
    .replace(/https?:\/\/\S+|www\.\S+/gi, "[URL]")
    .replace(/\b\d+\b/g, "[NUM]");
}

function group(source, text) {
  return `${source}:${crypto.createHash("sha1").update(template(text)).digest("hex").slice(0, 16)}`;
}

async function fetchText(page, url) {
  await page.goto(url, { waitUntil: "domcontentloaded" });
  return page.locator("body").innerText();
}

async function main() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const browser = await chromium.launch({ headless: true, executablePath: process.env.PW_CHROMIUM_PATH || undefined });
  const page = await browser.newPage();
  const phishingRaw = await fetchText(page, SOURCES.phishing);
  const legacyRaw = await fetchText(page, SOURCES.legacy);
  await browser.close();

  const records = [];
  const seen = new Set();
  const phishingRows = parseCsv(phishingRaw);
  const header = phishingRows.shift();
  const messageIndex = header.findIndex((value) => value === "message");
  const timeIndex = header.findIndex((value) => value === "time");
  for (const row of phishingRows) {
    const text = clean(row[messageIndex] || "");
    if (!text) continue;
    const key = `phishing:${text.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    records.push({ id: `wspr-${records.length}`, text, label: 1, campaign: group("wspr", text), source: "wspr-ncsu/sms-phishing", observed_at: row[timeIndex] || null });
  }

  let legacyIndex = 0;
  for (const line of legacyRaw.split(/\r?\n/)) {
    const match = line.match(/^(ham|spam)\s+([\s\S]*)$/i);
    if (!match) continue;
    const text = clean(match[2]);
    if (!text) continue;
    records.push({ id: `sms-spam-${legacyIndex}`, text, label: match[1].toLowerCase() === "spam" ? 1 : 0, campaign: group("legacy", text), source: "SMS Spam Collection v1", observed_at: null });
    legacyIndex += 1;
  }

  const out = path.join(DATA_DIR, "public_sms.jsonl");
  fs.writeFileSync(out, records.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");
  fs.writeFileSync(path.join(DATA_DIR, "public_sms.sources.json"), JSON.stringify({
    collected_at: new Date().toISOString(),
    collection_method: "Playwright browser extraction from publicly accessible pages",
    sources: [
      { name: "SMS Phishing Dataset", url: SOURCES.phishing, repository: "https://github.com/wspr-ncsu/sms-phishing", license_note: "Repository displays MIT license; cite Nahapetyan et al., IEEE S&P 2024." },
      { name: "SMS Spam Collection v1", url: SOURCES.legacy, repository: "https://github.com/nitish-niraj/sms-spam", license_note: "Corpus readme requests attribution to Almeida, Gómez Hidalgo and Yamakami and states free use with disclaimer." },
    ],
    records: records.length,
    positives: records.filter((row) => row.label === 1).length,
    negatives: records.filter((row) => row.label === 0).length,
    redactions: ["phone numbers", "email addresses"],
  }, null, 2) + "\n", "utf8");
  console.log(JSON.stringify({ records: records.length, positives: records.filter((row) => row.label === 1).length, negatives: records.filter((row) => row.label === 0).length, output: out }, null, 2));
}

main().catch((error) => { console.error(error); process.exit(1); });
