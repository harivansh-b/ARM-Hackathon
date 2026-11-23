const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const api = async (url, body, form) => {
  const opt = form ? { method: "POST", body: form } : body !== undefined ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {};
  const r = await fetch(url, opt); const j = await r.json().catch(() => ({ error: "bad response" }));
  if (!r.ok) throw new Error(j.error || r.statusText); return j;
};
const store = {  // survives a full reload (F5) within this tab; cleared when the tab closes
  get(k) { try { return JSON.parse(sessionStorage.getItem("guardian." + k)); } catch { return null; } },
  set(k, v) { try { sessionStorage.setItem("guardian." + k, JSON.stringify(v, (key, val) => key === "llm_loading" ? undefined : val)); } catch { } },
};
const STATE = { ALERT: ["Scam likely", "bad"], REVIEW: ["Needs review", "warn"], BENIGN_CANDIDATE: ["No strong signal", "ok"] };
const sample = [
  ["Bank KYC", "Dear customer your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.top/login"],
  ["UPI refund (Hinglish)", "Aapka refund Rs 2,499 pending hai. Paisa paane ke liye apna UPI PIN yahan daalein http://refund-upi.top"],
  ["Real OTP", "482913 is your OTP for HDFC Bank NetBanking login. Do not share it with anyone."],
];
const pages = { sms: pgCheck, network: pgSensor, system: pgSystem };
const alias = { check: "sms", import: "sms", sensor: "network" };
const panes = {}; let current = null;  // each page renders once into its own pane; switching only shows/hides

function route() {
  let p = (location.hash.slice(1) || "sms"); p = alias[p] || p; const id = pages[p] ? p : "sms";
  document.querySelectorAll("nav a").forEach(a => a.classList.toggle("on", a.dataset.p === id));
  current = id;
  if (!panes[id]) { const el = document.createElement("section"); el.className = "pane"; $("#main").appendChild(el); panes[id] = el; pages[id](el); }
  Object.entries(panes).forEach(([k, el]) => { el.style.display = k === id ? "" : "none"; });
}
addEventListener("hashchange", route);
async function status() {
  try { const s = await api("/api/status"); const c = $("#chip-llama"); c.className = "chip " + (s.llama_ready ? "ok" : "bad");
    c.lastChild.textContent = s.llama_ready ? "Llama 3.2 ready" : "Llama not found · templates"; } catch { }
}

/* ---------- Message check ---------- */
function highlight(text, signals) {
  let out = esc(text);
  [...new Set(signals.map(s => s.matched).filter(Boolean))].sort((a, b) => b.length - a.length).forEach(m => {
    const e = esc(m); if (e) out = out.split(e).join(`<mark>${e}</mark>`);
  }); return out;
}
function splitMessages(t) {
  const lines = t.split(/\n/).map(s => s.trim()).filter(Boolean);
  const hdr = /^(label|class|type|category)\s*,\s*(text|message|sms|body|content)$/i;
  const row = /^(scam|ham|spam|smish|phish|legit|benign|0|1)\s*,\s*"?([\s\S]*?)"?$/i;
  const csv = lines.filter(l => row.test(l)).length >= Math.max(2, Math.ceil(lines.length * 0.6));
  if (csv || (lines.length && hdr.test(lines[0]))) {  // pasted CSV: drop the header, move the label out of the message text
    return lines.filter(l => !hdr.test(l)).map(l => { const m = l.match(row); return m ? { label: m[1], text: m[2].replace(/""/g, '"') } : { text: l }; });
  }
  const blocks = t.split(/\n\s*\n/).map(s => s.trim()).filter(Boolean);
  return (blocks.length > 1 ? blocks : lines).map(text => ({ text }));
}
function evalStrip(r) {
  const e = r.eval; if (!e) return "";
  const pct = v => v == null ? "–" : Math.round(v * 100) + "%";
  return `<div class="card evalbar"><b>Checked against the file's labels</b><div class="row" style="gap:22px;margin-top:6px"><span><b>${pct(e.accuracy)}</b> <span class="sub">correct (${e.tp + e.tn}/${e.labelled})</span></span><span><b>${e.tp}/${e.scams}</b> <span class="sub">scams caught</span></span><span><b>${e.fp}/${e.hams}</b> <span class="sub">normal messages flagged</span></span></div><div class="sub" style="margin-top:4px">${esc(e.note)}</div></div>`;
}
function pgCheck(root) {
  const $ = (s, r = root) => r.querySelector(s);
  root.innerHTML = `<h1>SMS Scam Detection</h1><p class="lede">Check one message, or scan a whole export below. A local detector gives the verdict; Llama explains the evidence on-device. Nothing leaves this machine.</p>
  <div class="card"><textarea id="txt" placeholder="Paste the SMS here…"></textarea>
  <div class="row sb" style="margin-top:10px"><div class="row" style="flex:1"><input type="text" id="snd" placeholder="Sender (optional, e.g. +919901122334)" style="max-width:300px"></div><button id="go">Analyze</button></div>
  <div class="ex" style="margin-top:10px">Try: ${sample.map((s, i) => `<button data-i="${i}">${esc(s[0])}</button>`).join("")}</div></div><div id="res"></div><h2 style="margin-top:46px">Scan a message file</h2><div id="imp"></div>`;
  importUI($("#imp"));
  const S = store.get("sms") || {}; const save = () => store.set("sms", S);
  $("#txt").value = S.txt || ""; $("#snd").value = S.snd || "";
  $("#snd").addEventListener("input", () => { S.snd = $("#snd").value; save(); });
  root.querySelectorAll(".ex button").forEach(b => b.onclick = () => { $("#txt").value = sample[b.dataset.i][1]; run(); });
  let forceOne = false;
  $("#txt").addEventListener("input", () => { forceOne = false; S.txt = $("#txt").value; save(); });
  $("#go").onclick = run; $("#txt").addEventListener("keydown", e => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) run(); });
  async function run() {
    const text = $("#txt").value.trim(); if (!text) return; const res = $("#res");
    $("#go").disabled = true; res.innerHTML = "";
    S.txt = $("#txt").value; S.snd = $("#snd").value; S.res = null; save();
    const parts = splitMessages(text);
    if (parts.length > 1 && !forceOne) {
      try {
        const r = await api("/api/check-batch", { messages: parts, sender: $("#snd").value });
        r.filename = "Pasted text";
        S.res = { kind: "batch", n: parts.length, r }; save(); showBatch(parts.length, r);
      } catch (e) { res.innerHTML = `<div class="err">${esc(e.message)}</div>`; } finally { $("#go").disabled = false; }
      return;
    }
    forceOne = false;
    try {
      const r = await api("/api/check", { text, sender: $("#snd").value });
      S.res = { kind: "single", text, r }; save();
      render(r, text);
      if (r.flagged && r.llama_available) llm(text);
    } catch (e) { res.innerHTML = `<div class="err">${esc(e.message)}</div>`; } finally { $("#go").disabled = false; }
  }
  async function llm(text) {
    const box = $("#expl"); box.className = "expl loading"; box.innerHTML = `<span class="spin"></span>Llama is writing an explanation… (showing the built-in explanation meanwhile)`;
    try {
      const r = await api("/api/check", { text, sender: $("#snd").value, llm: true });
      explBlock(r.advice);
      if (S.res && S.res.kind === "single" && S.res.text === text) { S.res.r.advice = r.advice; save(); }
    } catch (e) { box.className = "expl"; box.innerHTML = esc(e.message); }
  }
  function showBatch(n, r) {
    $("#res").innerHTML = `<div class="card" style="margin-top:16px"><b>${n} messages detected</b> <span class="sub">(separated by blank lines or line breaks).</span> <button class="sm ghost" id="one">Analyze as one message instead</button></div><div id="bres"></div>`;
    $("#one").onclick = () => { forceOne = true; run(); };
    renderBatch($("#bres"), r, save);
  }
  function explBlock(a) {
    const box = $("#expl"); box.className = "expl";
    const st = a.llm_stats || {}; const meta = [a.llm_seconds ? a.llm_seconds + " s" : "", st.decode_tok_s ? st.decode_tok_s + " tok/s" : "", st.ttft_ms ? "TTFT " + st.ttft_ms + " ms" : ""].filter(Boolean).join(" · ");
    box.innerHTML = `<p style="margin:0 0 8px">${esc(a.text)}</p><span class="tag ${a.source === "llama" ? "llama" : ""}">${a.source === "llama" ? "Llama 3.2 · verified" : "Built-in template"}</span> <span class="sub">verifier: ${esc(a.verifier)}${meta ? " · " + meta : ""}</span>`;
    if (a.source === "template" && a.llm_raw) box.innerHTML += `<p class="sub" style="margin:8px 0 0">The Llama draft failed verification and was discarded, so the deterministic text is shown.</p>`;
  }
  function render(r, text) {
    const [label, k] = STATE[r.state] || [r.state, "ok"];
    $("#res").innerHTML = `<h2>Verdict</h2><div class="verdict ${r.state}"><div class="big">${label}</div><div><div class="row sb"><b>${esc(r.risk_tier)} risk</b><span class="sub">score ${r.score.toFixed(3)} · ${r.latency_ms} ms · ${esc(r.language || "")}</span></div><div class="meter" style="color:var(--${k})"><i style="width:${Math.round(r.score * 100)}%"></i></div><span class="sub">Decided by the on-device detector, independent of the language model.${r.state === "BENIGN_CANDIDATE" ? " Not a guarantee of safety." : ""}</span></div></div>
    <div class="grid2" style="margin-top:16px"><div><h2>Evidence</h2><div class="card"><div class="msg">${highlight(text, r.signals)}</div></div>
    ${r.signals.length ? `<ul class="plain card" style="margin-top:10px">${r.signals.map(s => `<li><b>${esc(s.signal)}</b> <span class="sub">“${esc(s.matched)}”</span></li>`).join("")}</ul>` : ""}
    ${r.urls.map(u => `<div class="card" style="margin-top:10px"><span class="tag ${u.tier === "INFO" ? "" : "warn"}">${esc(u.tier)}</span> <b>${esc(u.domain)}</b><div class="sub">${esc(u.url)}${u.reasons.length ? "<br>" + u.reasons.map(esc).join("; ") : ""}</div></div>`).join("")}
    ${r.story.length ? `<div class="sub" style="margin-top:8px">Linked evidence: ${r.story.map(s => esc(s.relation)).join(", ")}</div>` : ""}</div>
    <div><h2>Explanation</h2><div class="card"><div class="expl" id="expl"></div></div>
    <h2>Approved actions</h2><div class="card">${r.actions.length ? `<ul class="plain actions">${r.actions.map(a => `<li>${esc(a)}</li>`).join("")}</ul><div class="sub" style="margin-top:8px">Fixed playbook text — never generated or reworded by the model.</div>` : `<span class="sub">No action needed. Stay cautious with unexpected links or requests.</span>`}</div>
    ${r.model_evidence.length ? `<h2>Model features</h2><div class="card">${(m => r.model_evidence.map(f => `<div class="bar" title="${esc(f.feature)}"><span>${esc(f.feature.replace(/^[wc]:/, ""))}</span><div><i class="${f.contribution >= 0 ? "p" : "n"}" style="width:${Math.min(50, Math.abs(f.contribution) / m * 50)}%"></i></div><span>${f.contribution > 0 ? "+" : ""}${f.contribution.toFixed(2)}</span></div>`).join(""))(Math.max(...r.model_evidence.map(f => Math.abs(f.contribution))) || 1)}</div>` : ""}</div></div>`;
    explBlock(r.advice);
  }
  if (S.res) { if (S.res.kind === "batch") showBatch(S.res.n, S.res.r); else render(S.res.r, S.res.text); }
}

/* ---------- Import ---------- */
function importUI(root) {
  const $ = (s, r = root) => r.querySelector(s);
  root.innerHTML = `<p class="lede" style="margin-top:0">Import a message export — CSV, JSON, JSONL or plain text. Every message is analysed locally.</p>
  <label class="drop" id="drop"><input type="file" id="file" accept=".csv,.json,.jsonl,.txt" hidden><b>Drop a file here</b> or click to browse<br><span class="sub">Columns recognised: text/body/message, sender/address</span></label>
  <div class="row" style="margin-top:10px"><button class="ghost" id="smp">Use the bundled sample</button></div><div id="ires"></div>`;
  const drop = $("#drop"), file = $("#file");
  file.onchange = () => file.files[0] && up(file.files[0]);
  ["dragover", "dragenter"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => e.dataTransfer.files[0] && up(e.dataTransfer.files[0]));
  $("#smp").onclick = () => go(() => api("/api/import-sample", {}));
  const up = f => { const fd = new FormData(); fd.append("file", f); go(() => api("/api/import", undefined, fd)); };
  async function go(fn) {
    $("#ires").innerHTML = `<p class="sub"><span class="spin"></span>Analysing…</p>`;
    try { const r = await fn(); store.set("sms.import", r); renderBatch($("#ires"), r, () => store.set("sms.import", r)); } catch (e) { $("#ires").innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  }
  const sv = store.get("sms.import"); if (sv) renderBatch($("#ires"), sv, () => store.set("sms.import", sv));
}

function renderBatch(box, r, onChange) {
    let filter = "ALL"; const c = r.counts;
    box.innerHTML = `<h2>${esc(r.filename)} · ${r.total} messages · ${r.elapsed_ms} ms</h2>
    <div class="tiles"><div class="tile"><b>${r.total}</b><span>Messages</span></div><div class="tile"><b style="color:var(--bad)">${c.ALERT || 0}</b><span>Scam likely</span></div><div class="tile"><b style="color:var(--warn)">${c.REVIEW || 0}</b><span>Needs review</span></div><div class="tile"><b style="color:var(--ok)">${c.BENIGN_CANDIDATE || 0}</b><span>No strong signal</span></div></div>
    ${evalStrip(r)}<div class="row sb"><div class="tabs">${["ALL", "ALERT", "REVIEW", "BENIGN_CANDIDATE"].map(f => `<button data-f="${f}" class="${f === "ALL" ? "on" : ""}">${f === "ALL" ? "All" : STATE[f][0]}</button>`).join("")}</div><button class="ghost sm" id="exp">Export JSON</button></div>
    <table><thead><tr><th>Verdict</th><th>Score</th><th>Sender</th><th>Message</th>${r.eval ? "<th>Label</th>" : ""}<th></th></tr></thead><tbody id="tb"></tbody></table>`;
    box.querySelector("#exp").onclick = () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" })); a.download = "guardian_import_report.json"; a.click(); };
    box.querySelectorAll(".tabs button").forEach(b => b.onclick = () => { filter = b.dataset.f; box.querySelectorAll(".tabs button").forEach(x => x.classList.toggle("on", x === b)); rows(); });
    function rows() {
      const tb = box.querySelector("#tb"); const list = r.rows.filter(x => filter === "ALL" || x.state === filter);
      tb.innerHTML = list.length ? "" : `<tr><td colspan="6" class="empty">Nothing here.</td></tr>`;
      list.forEach(x => {
        const tr = document.createElement("tr"); tr.className = "r"; const [l, k] = STATE[x.state] || [x.state, ""];
        tr.innerHTML = `<td><span class="tag ${k}">${l}</span></td><td>${x.score.toFixed(2)}</td><td>${esc(x.sender || "–")}</td><td class="t">${esc(x.text)}</td>${r.eval ? `<td>${x.label ? esc(x.label) + (x.correct ? ' <span class="tag ok">✓</span>' : ' <span class="tag bad">✗</span>') : "–"}</td>` : ""}<td class="xc"><button class="xbtn">Explain with Llama</button></td>`;
        let open = null; const toggle = () => {
          if (open) { open.remove(); open = null; return; }
          open = document.createElement("tr"); open.className = "d";
          open.innerHTML = `<td colspan="6"><div class="msg">${esc(x.text)}</div>${x.signals.length ? `<p class="sub">Signals: ${x.signals.map(esc).join(" · ")}</p>` : ""}
          ${x.state !== "BENIGN_CANDIDATE" ? `<div class="expl" id="e${x.id}">${x.llm_advice ? adviceHTML(x.llm_advice) : `${esc(x.explanation)} <span class="tag">template</span>`}</div><ul class="plain actions">${x.actions.map(a => `<li>${esc(a)}</li>`).join("")}</ul>` : `<span class="sub">No strong scam signal. Not a guarantee of safety.</span><div class="expl" style="margin-top:8px"></div>`}</td>`;
          tr.after(open);
        };
        const adviceHTML = a => `${esc(a.text)} <span class="tag ${a.source === "llama" ? "llama" : ""}">${a.source === "llama" ? "Llama · verified" : "template"}</span> <span class="sub">${esc(a.verifier || "")}${a.llm_seconds ? " · " + a.llm_seconds + " s" : ""}</span>${a.source === "template" && a.llm_raw ? `<p class="sub">The Llama draft failed verification, so the built-in text is shown.</p>` : ""}`;
        tr.onclick = toggle; const bt = tr.querySelector(".xbtn"); if (bt) bt.onclick = async ev => {
          ev.stopPropagation(); if (!open) toggle();
          if (x.llm_loading) return; x.llm_loading = true; bt.disabled = true; bt.innerHTML = `<span class="spin"></span>Llama…`;
          try { const j = await api("/api/check", { text: x.text, sender: x.sender, llm: true }); const a = j.advice;
            x.llm_advice = a; if (onChange) onChange(); if (open) open.querySelector(".expl").innerHTML = adviceHTML(a);
            bt.disabled = false; bt.textContent = "Explain again";
          } catch (e) { bt.disabled = false; bt.textContent = "Failed – retry"; }
          finally { x.llm_loading = false; }
        };
        if (x.llm_advice && bt) bt.textContent = "Explain again";
        tb.appendChild(tr);
      });
    }
    rows();
  }

/* ---------- Network sensor ---------- */
function pgSensor(root) {
  const $ = (s, r = root) => r.querySelector(s);
  root.innerHTML = `<h1>Network Anomaly Detection</h1><p class="lede">Upload a packet capture (.pcap). Guardian analyses it offline and tells you, in plain words, whether anything suspicious happened.</p>
  <label class="drop" id="pdrop"><input type="file" id="pc" accept=".pcap" hidden><b>Drop a .pcap file here</b> or click to browse<br><span class="sub">Analysed on this device. Nothing is uploaded to the internet.</span></label>
  <div id="res"></div>
  <h3 class="step">Supported detection mechanisms</h3>
  <div class="scen" style="grid-template-columns:repeat(auto-fit,minmax(240px,1fr))">${[
    ["C2 beaconing", "Infected devices that “phone home” to an attacker at regular intervals."],
    ["DNS tunnelling", "Data smuggled out inside unusual, random-looking domain lookups."],
    ["Outbound port scan", "One device probing many ports to find weak spots."],
    ["Data exfiltration spike", "A sudden large upload to a single destination."],
    ["Smishing-to-network correlation", "Links a scam SMS to its URL, DNS lookup and later connections."]
  ].map(([t, d]) => `<div class="card"><b style="font:600 18px var(--serif)">${t}</b><div class="sub" style="margin-top:4px">${d}</div></div>`).join("")}</div>`;
  let cur = null;
  const up = async f => { if (!f) return; const fd = new FormData(); fd.append("file", f); await load(() => api("/api/sensor/upload", undefined, fd)); };
  $("#pc").onchange = e => up(e.target.files[0]);
  const dz = $("#pdrop");
  ["dragover", "dragenter"].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.add("over"); }));
  ["dragleave", "drop"].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.remove("over"); }));
  dz.addEventListener("drop", e => up(e.dataTransfer.files[0]));
  async function load(fn, id) {
    $("#res").innerHTML = `<p class="sub"><span class="spin"></span>Analysing ${id ? esc(id) : "your capture"}…</p>`;
    try { const r = await fn(); cur = { r, id }; store.set("net", r); show(r); } catch (e) { $("#res").innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  }
  function show(r) {
    const L = l => r.events.find(e => e.layer === l);
    const nodes = [["SMS", "Text message"], ["URL", "Link"], ["DNS", "Site lookup"], ["CONN", "Connection"], ["ALERT", "Alert"]].filter(([k]) => k === "ALERT" || k === "CONN" || k === "DNS" || L(k));
    const n = r.alerts.length, clean = r.verdict === "CLEAN" || !n, cls = clean ? "ok" : (r.alerts.some(a => a.evidence.risk_tier !== "WARN") ? "bad" : "warn");
    $("#res").innerHTML = `<div class="banner ${cls}"><div style="font-size:34px">${clean ? "✅" : "⚠️"}</div><div><div class="big">${clean ? "Nothing suspicious found" : n + " threat" + (n > 1 ? "s" : "") + " found"}</div><div class="sub">${esc(r.title)} — ${esc(r.blurb)}</div></div></div>
    <h3 class="step">What happened, step by step</h3>
    <div class="chain" id="chain">${nodes.map(([k, nm], i) => `${i ? '<div class="arrow">→</div>' : ""}<div class="node" data-l="${k}"><b>${nm.toUpperCase()}</b><span>–</span></div>`).join("")}</div>
    <div id="als"></div>
    <details class="more"><summary>Technical details (packet timeline)</summary>
      <div class="sub">${esc((r.source || "").split("/").pop())} · ${r.packets} packets · analysed in ${r.elapsed_ms} ms · recorded capture replayed offline, not live traffic</div>
      <div class="row" style="margin:8px 0"><button class="sm ghost" id="rp">↻ Replay</button><button class="sm ghost" id="sk">Skip</button></div>
      <div class="tl" id="tl"></div></details>`;
    let timer, i = 0; const tl = $("#tl");
    const add = e => {
      const d = document.createElement("div"); d.className = "ev " + e.layer;
      d.innerHTML = `<time>+${e.t.toFixed(2)}s</time><div class="lay">${e.layer}${e.scenario_input ? " · scenario input" : ""}</div><div class="ti">${esc(e.title)}</div><div class="de">${esc(e.detail)}</div>`; tl.appendChild(d);
      const nd = root.querySelector(`.node[data-l="${e.layer}"]`) || (e.layer === "TLS" && root.querySelector('.node[data-l="CONN"]'));
      if (nd && !nd.classList.contains("lit")) { nd.classList.add("lit"); if (e.layer === "ALERT") nd.classList.add("hot"); nd.querySelector("span").textContent = e.layer === "ALERT" ? e.title.split(" · ")[0] : (e.entity || e.title).toString().slice(0, 40); }
    };
    const reset = () => { clearInterval(timer); tl.innerHTML = ""; i = 0; root.querySelectorAll(".node").forEach(x => { x.className = "node"; x.querySelector("span").textContent = "–"; }); };
    const run = () => { reset(); if (!r.events.length) { tl.innerHTML = `<div class="empty">Nothing noteworthy observed.</div>`; return; } timer = setInterval(() => { if (i >= r.events.length) return clearInterval(timer); add(r.events[i++]); }, 650); };
    $("#rp").onclick = run; $("#sk").onclick = () => { clearInterval(timer); while (i < r.events.length) add(r.events[i++]); };
    run(); alerts(r);
  }
  function advHTML(a) {
    return `${esc(a.text)} <span class="tag ${a.source === "llama" ? "llama" : ""}">${a.source === "llama" ? "Llama 3.2 · verified" : "Built-in template"}</span> <span class="sub">${esc(a.verifier)}${a.llm_seconds ? " · " + a.llm_seconds + " s" : ""}</span>${a.source === "template" && a.llm_raw ? `<p class="sub">The Llama draft failed verification, so the built-in text is shown.</p>` : ""}`;
  }
  function alerts(r) {
    const box = $("#als"); if (!r.alerts.length) return;
    box.innerHTML = `<h3 class="step">What Guardian found</h3>` + r.alerts.map((a, k) => `<div class="card acard"><div class="row sb"><div class="hd">${esc(a.evidence.event_type)} <span class="tag ${a.evidence.risk_tier === "WARN" ? "warn" : "bad"}">${esc(a.evidence.risk_tier)}</span></div><span class="sub">${esc(a.evidence.entity.value)}</span></div>
    <div class="expl" id="ne${k}" style="margin-top:8px">${a.llm ? advHTML(a.llm) : esc(a.advice.text) + ' <span class="tag">template</span>'}</div>
    ${r.llama_available ? `<button class="xbtn" data-k="${k}"${a.llm ? " disabled" : ""}>${a.llm ? "Explained ✓" : "Explain with Llama"}</button>` : `<div class="sub" style="margin-top:8px">Llama not available – showing built-in explanation.</div>`}
    <details class="more"><summary>Why was this flagged? (score ${a.evidence.score.toFixed(2)})</summary><ul class="plain">${a.evidence.reasons.map(x => `<li class="sub">${esc(x)}</li>`).join("")}</ul>${a.escalated_from && a.escalated_from.length > 1 ? `<div class="sub">Escalated ${a.escalated_from.map(esc).join(" → ")} as more evidence arrived.</div>` : ""}</details></div>`).join("");
    box.querySelectorAll(".xbtn").forEach(bt => bt.onclick = async () => {
      const k = +bt.dataset.k, b = $("#ne" + k); bt.disabled = true; bt.innerHTML = `<span class="spin"></span>Llama is writing…`;
      try { const a = await api("/api/sensor/explain", { evidence: r.alerts[k].evidence });
        b.innerHTML = advHTML(a); bt.textContent = "Explained ✓"; r.alerts[k].llm = a; store.set("net", r);
      } catch (e) { bt.disabled = false; bt.textContent = "Failed – retry"; }
    });
  }
  const sv = store.get("net"); if (sv) { cur = { r: sv }; show(sv); $("#sk").click(); }  // restore last capture result (timeline shown fully, no replay)
}

/* ---------- Sustained run ---------- */
function chart(title, unit, pts, color) {
  const v = pts.filter(p => p[1] != null); if (v.length < 2) return `<div class="ch"><b>${esc(title)}</b><div class="sub">collecting…</div></div>`;
  const W = 300, H = 70, xs = v.map(p => p[0]), ys = v.map(p => p[1]); const x0 = xs[0], x1 = xs[xs.length - 1] || 1;
  let lo = Math.min(...ys), hi = Math.max(...ys); if (hi === lo) { hi += 1; lo -= 1; } const pad = (hi - lo) * 0.1; lo -= pad; hi += pad;
  const path = v.map((p, i) => `${i ? "L" : "M"}${((p[0] - x0) / (x1 - x0 || 1) * W).toFixed(1)},${(H - (p[1] - lo) / (hi - lo) * H).toFixed(1)}`).join("");
  const last = ys[ys.length - 1];
  return `<div class="ch"><div class="row sb"><b>${esc(title)}</b><span class="sub"><b style="color:var(--ink)">${last}</b> ${esc(unit)} · min ${Math.min(...ys)} · max ${Math.max(...ys)}</span></div><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><path d="${path}" fill="none" stroke="${color}" stroke-width="1.8" vector-effect="non-scaling-stroke"/></svg></div>`;
}
function sustainedUI(root) {
  const $ = (s, r = root) => r.querySelector(s);
  let timer = null, pollBusy = false, generation = 0, last = null;
  const box = root;
  box.innerHTML = `<p class="sub" style="margin:0 0 12px">Runs the SMS detector and network sensor continuously in the background and charts how this machine copes over time: speed, memory, CPU and temperature. Turn it off whenever you like to freeze the charts and read the summary.</p>
  <div class="row sb"><label class="sw"><input type="checkbox" id="sw"><span class="knob"></span><b id="swl">Sustained run is off</b></label></div><div id="srb" style="margin-top:14px"></div>`;
  const sw = $("#sw");
  const render = st => {
    last = st; sw.checked = !!st.running; const elapsed = Number(st.elapsed_s || 0);
    $("#swl").textContent = st.running ? `Running · ${elapsed}s` : st.has_data ? "Stopped — showing the last run" : "Sustained run is off";
    if (!st.has_data) { $("#srb").innerHTML = (st.error ? `<div class="err">${esc(st.error)}</div>` : "") + (st.running ? `<div class="sub">Collecting metrics · ${elapsed}s elapsed.</div>` : ""); return; }
    const S = st.samples || [], P = k => S.map(s => [s.t, s[k]]), m = st.summary;
    const tiles = m ? `<div class="tiles" style="margin-bottom:12px"><div class="tile"><b>${m.duration_s}s</b><span>Duration</span></div><div class="tile"><b>${Number(m.ops_per_s_mean || 0).toLocaleString()}</b><span>Messages/s average</span></div><div class="tile"><b style="color:${m.throughput_drift_pct != null && m.throughput_drift_pct < -10 ? "var(--bad)" : "var(--ok)"}">${m.throughput_drift_pct == null ? "–" : (m.throughput_drift_pct > 0 ? "+" : "") + m.throughput_drift_pct + "%"}</b><span>Speed change, start → end</span></div><div class="tile"><b>${m.rss_mb_peak ?? "–"} MB</b><span>Guardian peak memory</span></div></div>` : "";
    $("#srb").innerHTML = (st.error ? `<div class="err">${esc(st.error)}</div>` : "") + tiles + `<div class="charts">
      ${chart("Throughput", "msgs/s", P("ops_per_s"), "var(--moss)")}${chart("Detector latency p95", "ms", P("lat_p95_ms"), "var(--warn)")}
      ${chart("Guardian memory", "MB", P("rss_mb"), "var(--moss)")}${chart("Machine memory in use", "MB", P("mem_used_mb"), "var(--warn)")}
      ${chart("CPU busy (all cores)", "%", P("sys_cpu_pct"), "var(--bad)")}
      ${st.temp_available ? chart("CPU temperature", "°C", P("temp_c"), "var(--bad)") : `<div class="ch"><b>CPU temperature</b><div class="sub">No temperature sensor is exposed on this machine (typical for VMs).</div></div>`}
      </div>
      ${m && !st.running ? `<h2 style="margin-top:16px">Summary</h2><div class="card"><dl class="kv">
        <dt>Messages analysed</dt><dd>${m.total_ops.toLocaleString()} in ${m.duration_s}s (${m.ops_per_s_min}–${m.ops_per_s_max} msgs/s)</dd>
        <dt>Slowest 5% latency</dt><dd>${m.lat_p95_ms_worst} ms at worst</dd>
        <dt>Memory</dt><dd>Guardian ${m.rss_mb_start ?? "–"} → ${m.rss_mb_end ?? "–"} MB · machine ${m.mem_used_mb_start ?? "–"} → ${m.mem_used_mb_end ?? "–"} MB</dd>
        <dt>CPU busy</dt><dd>${m.sys_cpu_pct_mean ?? "–"}% average</dd>
        <dt>Temperature</dt><dd>${m.temp_c_start != null ? `${m.temp_c_start} → ${m.temp_c_end} °C (max ${m.temp_c_max})` : "not available"}</dd>
        <dt>Sensor replays</dt><dd>${m.sensor_replays} runs · ${m.sensor_replay_errors} errors · ${m.sensor_replay_seconds_total}s total replay time</dd></dl>
        <div class="row" style="margin-top:10px"><button class="sm ghost" id="dj">Download JSON</button><button class="sm ghost" id="dc">Download CSV</button></div></div>` : ""}`;
    const dl = (name, text, type) => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click(); };
    if ($("#dj")) { $("#dj").onclick = () => dl("guardian_sustained_run.json", JSON.stringify({ summary: m, samples: S }, null, 2), "application/json");
      $("#dc").onclick = () => { const k = Object.keys(S[0] || {}); dl("guardian_sustained_run.csv", [k.join(",")].concat(S.map(s => k.map(x => s[x] ?? "").join(","))).join("\n"), "text/csv"); }; }
  };
  const poll = async token => {
    if (pollBusy || token !== generation) return;
    pollBusy = true;
    try { const st = await api("/api/sustained"); if (token !== generation) return; render(st); if (!st.running) stopPolling(); }
    catch { /* transient polling failures should not terminate an active run */ }
    finally { pollBusy = false; }
  };
  const stopPolling = () => { if (timer) clearInterval(timer); timer = null; };
  const begin = () => { stopPolling(); const token = ++generation; timer = setInterval(() => poll(token), 2000); poll(token); };
  sw.onchange = async () => {
    sw.disabled = true; stopPolling(); const token = ++generation;
    try {
      if (sw.checked) { const st = await api("/api/sustained/start", {}); if (token !== generation) return; render(st); begin(); }
      else { $("#swl").textContent = "Stopping…"; const st = await api("/api/sustained/stop", {}); if (token !== generation) return; render(st); poll(token); }
    } catch (e) { $("#srb").innerHTML = `<div class="err">${esc(e.message)}</div>`; sw.checked = !!(last && last.running); if (last && last.running) begin(); }
    finally { sw.disabled = false; }
  };
  const token = generation;
  api("/api/sustained").then(st => { if (token !== generation) return; render(st); if (st.running) begin(); }).catch(() => {});
}

/* ---------- Live System Metrics ---------- */
function pgSystem(root) {
  const $ = (s, r = root) => r.querySelector(s);
  root.innerHTML = `<h1>Live System Metrics</h1><p class="lede">Everything on this page is read or measured on this machine, right now. Nothing is hard-coded or copied from earlier runs.</p><div id="sys"><span class="spin"></span></div>`;
  let timer;
  const fmtUp = s => s == null ? "–" : s >= 3600 ? Math.floor(s / 3600) + " h " + Math.floor(s % 3600 / 60) + " min" : Math.floor(s / 60) + " min";
  const row = (k, v, why) => `<dt>${k}</dt><dd>${v}${why ? `<div class="sub">${why}</div>` : ""}</dd>`;
  const live = s => {
    const used = s.mem_mb && s.mem_available_mb ? s.mem_mb - s.mem_available_mb : null; const o = s.offline;
    $("#live").innerHTML = `<h2>Is Guardian really offline?</h2><div class="card"><dl class="kv">
      ${row("Outbound connections", s.outbound_connections === 0 ? '<span class="tag ok">0 opened</span>' : `<span class="tag bad">${s.outbound_connections}</span>`, "Live count of network connections this Guardian process has opened to other machines. Zero means it is working fully offline.")}
      ${row("Network link", o.interfaces.length ? o.interfaces.map(i => `${esc(i.name)} (${esc(i.state)})`).join(", ") : "loopback only", "Used only to serve this page to your browser through the forwarded port; Guardian never sends data out through it.")}
      ${row("Default route", o.default_route ? '<span class="tag warn">exists on this VM</span>' : '<span class="tag ok">none</span>', "Whether this machine has a path to the internet. Detection, Llama and PCAP replay never use it, and no threat feeds or models are downloaded at runtime.")}
    </dl></div>
    <h2>Hardware running Guardian</h2><div class="card"><dl class="kv">
      ${row("Architecture", `${esc(s.arch)} ${s.arm64 ? '<span class="tag ok">Arm64</span>' : '<span class="tag warn">not Arm64</span>'}`, "The CPU instruction set. Guardian is built to run on Arm.")}
      ${row("Processor", `${esc(s.cpu || s.arch)} · ${s.cpus} cores`, "Cores available for detection and Llama inference.")}
      ${row("Memory", used != null ? `${used} MB in use of ${s.mem_mb} MB <div class="meter" style="color:var(--moss)"><i style="width:${Math.round(used / s.mem_mb * 100)}%"></i></div>` : "–", `Whole machine. Guardian's own web process is using about ${s.guardian_rss_mb ?? "–"} MB (without Llama, which runs separately and only when asked).`)}
      ${row("CPU load (1 / 5 / 15 min)", s.load ? s.load.join(" / ") : "–", `Average busy tasks; around ${s.cpus} would mean every core is fully busy.`)}
      ${row("CPU temperature", s.cpu_temp_c != null ? s.cpu_temp_c + " °C" : "not exposed", s.cpu_temp_c == null ? "Virtual machines usually have no temperature sensor." : "Read from the thermal sensor.")}
      ${row("Uptime", fmtUp(s.uptime_s), "Time since this machine booted.")}
      ${row("Kernel · Python", `${esc(s.kernel)} · ${esc(s.python)}`, "")}
    </dl></div>`;
  };
  const mrow = m => `<tr><td>${esc(m.name)}<div class="sub">${esc(m.path)}</div></td><td>${m.present ? (m.bytes / 1048576).toFixed(1) + " MB" : '<span class="tag warn">missing</span>'}</td><td class="hash">${m.sha256 || (m.present ? '<span class="spin"></span>computing…' : "–")}</td></tr>`;
  const kv = (o) => `<dl class="kv">${Object.entries(o).map(([k, [v, w]]) => row(k, esc(v), w)).join("")}</dl>`;
  api("/api/system").then(s => {
    $("#sys").innerHTML = `<div id="live"></div>
    <h2>AI models &amp; runtime files</h2><div class="card"><p class="sub" style="margin:0 0 10px">The SHA-256 is a fingerprint of each file. If even one byte changes, it changes — so matching the organiser's reference values proves these are the exact models that were approved.</p>
    <table><thead><tr><th>Artifact</th><th>Size</th><th>SHA-256</th></tr></thead><tbody id="mf">${s.models.map(mrow).join("")}</tbody></table></div>
    <div class="row sb"><h2>Measured performance</h2><button class="sm ghost" id="rb" style="margin-top:18px">↻ Re-measure</button></div>
    <div class="card" id="bo"></div>
    <h2>Sustained run</h2><div class="card" id="sr"></div>`;
    live(s); timer = setInterval(async () => { try { live(await api("/api/system")); } catch { } }, 3000);
    api("/api/system/hashes").then(m => { $("#mf").innerHTML = m.map(mrow).join(""); });
    const measure = async () => {
      $("#rb").disabled = true; $("#bo").innerHTML = `<span class="spin"></span>Measuring detector and network sensor…`;
      try {
        const r = await api("/api/system/benchmark", {});
        const base = kv({
          "SMS detector — median": [r.detector_p50_ms + " ms", `Typical time to decide whether one message is a scam (${r.detector_samples} runs).`],
          "SMS detector — slowest 5%": [r.detector_p95_ms + " ms", "95% of messages are decided at least this fast."],
          "Network sensor replay": [r.sensor_replay_ms + " ms", "Time to replay and analyse a full SMS → DNS → beacon capture."],
        });
        $("#bo").innerHTML = base + `<div id="lb" style="margin-top:6px"><span class="spin"></span>Measuring Llama (one real explanation, a few seconds)…</div>`;
        if (s.llama_ready) {
          const l = await api("/api/system/llama-benchmark", {}); const st = l.stats || {};
          $("#lb").innerHTML = `<h2 style="margin:14px 0 8px">Llama 3.2 on this machine</h2>` + kv({
            "Time for one explanation": [l.wall_seconds + " s", "Total time to load the model, read the evidence and write the explanation."],
            "Time to first token": [st.ttft_ms ? st.ttft_ms + " ms" : "not reported by runner", "How long before Llama starts answering."],
            "Generation speed": [st.decode_tok_s ? st.decode_tok_s + " tokens/s" : "not reported by runner", "How fast Llama writes (a token is roughly ¾ of a word)."],
            "Llama peak memory": [l.child_peak_rss_mb != null ? l.child_peak_rss_mb + " MB" : "–", "Largest memory the Llama process used."],
            "Output accepted": [l.source === "llama" ? "yes" : "no — " + l.verifier, "Whether Llama's text passed Guardian's safety verifier."],
          });
        } else $("#lb").innerHTML = `<span class="tag warn">Llama not found</span> <span class="sub">Place the runner and model files under runtime/ and models/ to measure it.</span>`;
        $("#bo").insertAdjacentHTML("beforeend", `<div class="sub" style="margin-top:10px">Measured at ${new Date().toLocaleTimeString()} on this machine.</div>`);
      } catch (e) { $("#bo").innerHTML = `<div class="err">${esc(e.message)}</div>`; }
      $("#rb").disabled = false;
    };
    $("#rb").onclick = measure; measure(); sustainedUI($("#sr"));
  }).catch(e => $("#sys").innerHTML = `<div class="err">${esc(e.message)}</div>`);
}

status(); route();
