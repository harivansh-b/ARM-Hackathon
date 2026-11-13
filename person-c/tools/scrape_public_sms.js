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
  multilingual: "https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset/resolve/main/data-augmented.csv",
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

async function fetchTextWithPlaywrightRequest(context, url) {
  const response = await context.request.get(url);
  if (!response.ok()) throw new Error(`failed to fetch ${url}: ${response.status()}`);
  return response.text();
}

async function main() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const executablePath = process.env.PW_CHROMIUM_PATH || (process.platform === "win32" ? "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" : undefined);
  const browser = await chromium.launch({ headless: true, executablePath });
  const context = await browser.newContext();
  const phishingRaw = await fetchTextWithPlaywrightRequest(context, SOURCES.phishing);
  const legacyRaw = await fetchTextWithPlaywrightRequest(context, SOURCES.legacy);
  const multilingualRaw = await fetchTextWithPlaywrightRequest(context, SOURCES.multilingual);
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

  const multilingualRecords = [];
  const multilingualSeen = new Set();
  const multilingualRows = parseCsv(multilingualRaw);
  const multilingualHeader = multilingualRows.shift() || [];
  const labelIndex = multilingualHeader.findIndex((value) => value === "labels");
  const englishIndex = multilingualHeader.findIndex((value) => value === "text");
  const hindiIndex = multilingualHeader.findIndex((value) => value === "text_hi");
  for (const row of multilingualRows) {
    const label = String(row[labelIndex] || "").toLowerCase();
    if (!label || (label !== "ham" && label !== "spam")) continue;
    const english = clean(row[englishIndex] || "");
    if (!english) continue;
    const campaign = group("multilingual", english);
    for (const variant of [
      { index: englishIndex, language: "en" },
      { index: hindiIndex, language: "hi" },
    ]) {
      const text = clean(row[variant.index] || "");
      const key = `${variant.language}:${text.toLowerCase()}`;
      if (!text || multilingualSeen.has(key)) continue;
      multilingualSeen.add(key);
      multilingualRecords.push({
        id: `sms-ml-${multilingualRecords.length}`,
        text,
        label: label === "spam" ? 1 : 0,
        campaign,
        language: variant.language,
        category: label === "spam" ? "spam" : "ham",
        source: "dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset",
      });
    }
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
  const multilingualOut = path.join(DATA_DIR, "public_sms_multilingual.jsonl");
  fs.writeFileSync(multilingualOut, multilingualRecords.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");
  fs.writeFileSync(path.join(DATA_DIR, "public_sms_multilingual.sources.json"), JSON.stringify({
    collected_at: new Date().toISOString(),
    collection_method: "Playwright browser request extraction from the Hugging Face public dataset file",
    source: {
      name: "SMS Spam Multilingual Collection Dataset",
      dataset_url: "https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset",
      file_url: SOURCES.multilingual,
      license: "GPL (as declared by the dataset card)",
      original_data_note: "The card says the English SMS Spam Collection was machine-translated into Hindi and other languages. Hindi quality must be reviewed before production claims.",
    },
    fields: ["en", "hi"],
    records: multilingualRecords.length,
    positives: multilingualRecords.filter((row) => row.label === 1).length,
    negatives: multilingualRecords.filter((row) => row.label === 0).length,
    redactions: ["phone numbers", "email addresses"],
    hinglish_note: "No verified Hinglish field was found; keep Hinglish examples separate and label them as synthetic or consented.",
  }, null, 2) + "\n", "utf8");
  console.log(JSON.stringify({
    records: records.length,
    positives: records.filter((row) => row.label === 1).length,
    negatives: records.filter((row) => row.label === 0).length,
    output: out,
    multilingual_records: multilingualRecords.length,
    multilingual_output: multilingualOut,
  }, null, 2));
}

main().catch((error) => { console.error(error); process.exit(1); });
