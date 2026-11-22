const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const api = async (url, body, form) => {
  const opt = form ? { method: "POST", body: form } : body !== undefined ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {};
  const r = await fetch(url, opt); const j = await r.json().catch(() => ({ error: "bad response" }));
  if (!r.ok) throw new Error(j.error || r.statusText); return j;
};
const STATE = { ALERT: ["Scam likely", "bad"], REVIEW: ["Needs review", "warn"], BENIGN_CANDIDATE: ["No strong signal", "ok"] };
const sample = [
  ["Bank KYC", "Dear customer your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.top/login"],
  ["UPI refund (Hinglish)", "Aapka refund Rs 2,499 pending hai. Paisa paane ke liye apna UPI PIN yahan daalein http://refund-upi.top"],
  ["Real OTP", "482913 is your OTP for HDFC Bank NetBanking login. Do not share it with anyone."],
];
const pages = { sms: pgCheck, network: pgSensor, system: pgSystem };
const alias = { check: "sms", import: "sms", sensor: "network" };
let seq = 0;

function route() {
  let p = (location.hash.slice(1) || "sms"); p = alias[p] || p; const id = pages[p] ? p : "sms";
  document.querySelectorAll("nav a").forEach(a => a.classList.toggle("on", a.dataset.p === id));
  seq++; pages[id](seq);
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
function pgCheck() {
  $("#main").innerHTML = `<h1>SMS Scam Detection</h1><p class="lede">Check one message, or scan a whole export below. A local detector gives the verdict; Llama explains the evidence on-device. Nothing leaves this machine.</p>
  <div class="card"><textarea id="txt" placeholder="Paste the SMS here…"></textarea>
  <div class="row sb" style="margin-top:10px"><div class="row" style="flex:1"><input type="text" id="snd" placeholder="Sender (optional, e.g. +919901122334)" style="max-width:300px"></div><button id="go">Analyze</button></div>
  <div class="ex" style="margin-top:10px">Try: ${sample.map((s, i) => `<button data-i="${i}">${esc(s[0])}</button>`).join("")}</div></div><div id="res"></div><h2 style="margin-top:46px">Scan a message file</h2><div id="imp"></div>`;
  importUI($("#imp"));
  document.querySelectorAll(".ex button").forEach(b => b.onclick = () => { $("#txt").value = sample[b.dataset.i][1]; run(); });
  let forceOne = false;
  $("#txt").addEventListener("input", () => { forceOne = false; });
  $("#go").onclick = run; $("#txt").addEventListener("keydown", e => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) run(); });
  async function run() {
    const text = $("#txt").value.trim(); if (!text) return; const my = seq; const res = $("#res");
    $("#go").disabled = true; res.innerHTML = "";
    const parts = splitMessages(text);
    if (parts.length > 1 && !forceOne) {
      try {
        const r = await api("/api/check-batch", { messages: parts, sender: $("#snd").value }); if (my !== seq) return;
        r.filename = "Pasted text";
        res.innerHTML = `<div class="card" style="margin-top:16px"><b>${parts.length} messages detected</b> <span class="sub">(separated by blank lines or line breaks).</span> <button class="sm ghost" id="one">Analyze as one message instead</button></div><div id="bres"></div>`;
        $("#one").onclick = () => { forceOne = true; run(); };
        renderBatch($("#bres"), r);
      } catch (e) { res.innerHTML = `<div class="err">${esc(e.message)}</div>`; } finally { $("#go").disabled = false; }
      return;
    }
    forceOne = false;
    try {
      const r = await api("/api/check", { text, sender: $("#snd").value });
      if (my !== seq) return; render(r, text);
      if (r.flagged && r.llama_available) llm(text, my);
    } catch (e) { res.innerHTML = `<div class="err">${esc(e.message)}</div>`; } finally { $("#go").disabled = false; }
  }
  async function llm(text, my) {
    const box = $("#expl"); box.className = "expl loading"; box.innerHTML = `<span class="spin"></span>Llama is writing an explanation… (showing the built-in explanation meanwhile)`;
    try {
      const r = await api("/api/check", { text, sender: $("#snd").value, llm: true }); if (my !== seq) return;
      explBlock(r.advice);
    } catch (e) { box.className = "expl"; box.innerHTML = esc(e.message); }
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
}

/* ---------- Import ---------- */
function importUI(root) {
  root.innerHTML = `<p class="lede" style="margin-top:0">Import a message export — CSV, XML (SMS Backup &amp; Restore), JSON, JSONL or plain text. Every message is analysed locally.</p>
  <label class="drop" id="drop"><input type="file" id="file" accept=".csv,.xml,.json,.jsonl,.txt" hidden><b>Drop a file here</b> or click to browse<br><span class="sub">Columns recognised: text/body/message, sender/address</span></label>
  <div class="row" style="margin-top:10px"><button class="ghost" id="smp">Use the bundled sample</button></div><div id="ires"></div>`;
  const drop = $("#drop"), file = $("#file");
  file.onchange = () => file.files[0] && up(file.files[0]);
  ["dragover", "dragenter"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => e.dataTransfer.files[0] && up(e.dataTransfer.files[0]));
  $("#smp").onclick = () => go(() => api("/api/import-sample", {}));
  const up = f => { const fd = new FormData(); fd.append("file", f); go(() => api("/api/import", undefined, fd)); };
  async function go(fn) {
    const my = seq; $("#ires").innerHTML = `<p class="sub"><span class="spin"></span>Analysing…</p>`;
    try { const r = await fn(); if (my === seq) renderBatch($("#ires"), r); } catch (e) { $("#ires").innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  }
}

function renderBatch(box, r) {
    let filter = "ALL"; const c = r.counts;
    box.innerHTML = `<h2>${esc(r.filename)} · ${r.total} messages · ${r.elapsed_ms} ms</h2>
    <div class="tiles"><div class="tile"><b>${r.total}</b><span>Messages</span></div><div class="tile"><b style="color:var(--bad)">${c.ALERT || 0}</b><span>Scam likely</span></div><div class="tile"><b style="color:var(--warn)">${c.REVIEW || 0}</b><span>Needs review</span></div><div class="tile"><b style="color:var(--ok)">${c.BENIGN_CANDIDATE || 0}</b><span>No strong signal</span></div></div>
    ${evalStrip(r)}<div class="row sb"><div class="tabs">${["ALL", "ALERT", "REVIEW", "BENIGN_CANDIDATE"].map(f => `<button data-f="${f}" class="${f === "ALL" ? "on" : ""}">${f === "ALL" ? "All" : STATE[f][0]}</button>`).join("")}</div><button class="ghost sm" id="exp">Export JSON</button></div>
    <table><thead><tr><th>Verdict</th><th>Score</th><th>Sender</th><th>Message</th>${r.eval ? "<th>Label</th>" : ""}</tr></thead><tbody id="tb"></tbody></table>`;
    box.querySelector("#exp").onclick = () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" })); a.download = "guardian_import_report.json"; a.click(); };
    box.querySelectorAll(".tabs button").forEach(b => b.onclick = () => { filter = b.dataset.f; box.querySelectorAll(".tabs button").forEach(x => x.classList.toggle("on", x === b)); rows(); });
    function rows() {
      const tb = box.querySelector("#tb"); const list = r.rows.filter(x => filter === "ALL" || x.state === filter);
      tb.innerHTML = list.length ? "" : `<tr><td colspan="5" class="empty">Nothing here.</td></tr>`;
      list.forEach(x => {
        const tr = document.createElement("tr"); tr.className = "r"; const [l, k] = STATE[x.state] || [x.state, ""];
        tr.innerHTML = `<td><span class="tag ${k}">${l}</span></td><td>${x.score.toFixed(2)}</td><td>${esc(x.sender || "–")}</td><td class="t">${esc(x.text)}</td>${r.eval ? `<td>${x.label ? esc(x.label) + (x.correct ? ' <span class="tag ok">✓</span>' : ' <span class="tag bad">✗</span>') : "–"}</td>` : ""}`;
        let open = null; tr.onclick = () => {
          if (open) { open.remove(); open = null; return; }
          open = document.createElement("tr"); open.className = "d";
          open.innerHTML = `<td colspan="5"><div class="msg">${esc(x.text)}</div>${x.signals.length ? `<p class="sub">Signals: ${x.signals.map(esc).join(" · ")}</p>` : ""}
          ${x.state !== "BENIGN_CANDIDATE" ? `<div class="expl" id="e${x.id}">${esc(x.explanation)} <span class="tag">template</span></div><div class="row" style="margin:8px 0"><button class="sm ghost">Explain with Llama</button></div><ul class="plain actions">${x.actions.map(a => `<li>${esc(a)}</li>`).join("")}</ul>` : `<span class="sub">No strong scam signal. Not a guarantee of safety.</span>`}</td>`;
          tr.after(open); const bt = open.querySelector("button"); if (bt) bt.onclick = async ev => {
            ev.stopPropagation(); bt.disabled = true; bt.innerHTML = `<span class="spin"></span>Llama…`;
            try { const j = await api("/api/check", { text: x.text, sender: x.sender, llm: true }); const a = j.advice;
              open.querySelector(".expl").innerHTML = `${esc(a.text)} <span class="tag ${a.source === "llama" ? "llama" : ""}">${a.source === "llama" ? "Llama · verified" : "template"}</span> <span class="sub">${esc(a.verifier)}${a.llm_seconds ? " · " + a.llm_seconds + " s" : ""}</span>`; bt.remove();
            } catch (e) { bt.textContent = "Failed: " + e.message; }
          };
        };
        tb.appendChild(tr);
      });
    }
    rows();
  }

/* ---------- Network sensor ---------- */
function pgSensor() {
  $("#main").innerHTML = `<h1>Network Anomaly Detection</h1><p class="lede">Replay a packet capture through the flow table and detectors, Pick a pre-recorded capture (.pcap file) below, then follow the attack across layers: SMS → URL → DNS → connection → alert. Each alert is then explained on-device by Llama.</p>
  <div class="scen" id="scen"></div><div class="row" style="margin-top:12px"><label class="btn ghost" style="background:transparent;color:var(--ink);border:1px solid var(--line)">Replay your own .pcap<input type="file" id="pc" accept=".pcap" hidden></label></div><div id="res"></div>`;
  let cur = null;
  api("/api/sensor/scenarios").then(list => {
    $("#scen").innerHTML = list.map(s => `<button data-id="${s.id}" ${s.available ? "" : "disabled"}><b>${esc(s.title)}</b><span>${esc(s.blurb)}</span><span class="file">${esc(s.file)}</span></button>`).join("");
    document.querySelectorAll("#scen button").forEach(b => b.onclick = () => play(b.dataset.id, b));
    play("smishing_c2_chain", $('#scen button[data-id="smishing_c2_chain"]'));
  });
  $("#pc").onchange = async e => { const f = e.target.files[0]; if (!f) return; const fd = new FormData(); fd.append("file", f); document.querySelectorAll("#scen button").forEach(x => x.classList.remove("on")); await load(() => api("/api/sensor/upload", undefined, fd)); };
  async function play(id, btn) { document.querySelectorAll("#scen button").forEach(x => x.classList.toggle("on", x === btn)); await load(() => api("/api/sensor/replay", { scenario: id }), id); }
  async function load(fn, id) {
    const my = seq; $("#res").innerHTML = `<p class="sub"><span class="spin"></span>Replaying ${id ? esc(id) + ".pcap" : "your capture"}…</p>`;
    try { const r = await fn(); if (my !== seq) return; cur = { r, id }; show(r, my); } catch (e) { $("#res").innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  }
  function show(r, my) {
    const L = l => r.events.find(e => e.layer === l);
    const nodes = [["SMS", "SMS"], ["URL", "URL"], ["DNS", "DNS"], ["CONN", "Connection"], ["ALERT", "Alert"]].filter(([k]) => k === "ALERT" || k === "CONN" || k === "DNS" || L(k));
    $("#res").innerHTML = `<div class="src"><span class="tag ok">Replaying</span> <b>${esc((r.source || "").split("/").pop())}</b><div class="sub">${esc(r.source || "")} · ${r.packets} packets · analysed in ${r.elapsed_ms} ms · pre-recorded capture replayed offline, not live traffic</div></div><h2>${esc(r.title)}</h2><p class="sub" style="margin-top:-4px">${esc(r.blurb)}</p>
    <div class="chain" id="chain">${nodes.map(([k, n], i) => `${i ? '<div class="arrow">→</div>' : ""}<div class="node" data-l="${k}"><b>${n.toUpperCase()}</b><span>–</span></div>`).join("")}</div>
    <div class="row sb" style="margin-top:14px"><h2 style="margin:0">Timeline</h2><div class="row"><span class="tag ${r.verdict === "CLEAN" ? "ok" : "bad"}">${r.verdict === "CLEAN" ? "No alerts" : r.alerts.length + " alert" + (r.alerts.length > 1 ? "s" : "")}</span><button class="sm ghost" id="rp">↻ Replay</button><button class="sm ghost" id="sk">Skip</button></div></div>
    <div class="tl" id="tl"></div><div id="als"></div>`;
    let timer, i = 0; const tl = $("#tl");
    const add = e => {
      const d = document.createElement("div"); d.className = "ev " + e.layer;
      d.innerHTML = `<time>+${e.t.toFixed(2)}s</time><div class="lay">${e.layer}${e.scenario_input ? " · scenario input" : ""}</div><div class="ti">${esc(e.title)}</div><div class="de">${esc(e.detail)}</div>`; tl.appendChild(d);
      const n = document.querySelector(`.node[data-l="${e.layer}"]`) || (e.layer === "TLS" && document.querySelector('.node[data-l="CONN"]'));
      if (n && !n.classList.contains("lit")) { n.classList.add("lit"); if (e.layer === "ALERT") n.classList.add("hot"); n.querySelector("span").textContent = e.layer === "ALERT" ? e.title.split(" · ")[0] : (e.entity || e.title).toString().slice(0, 40); }
    };
    const reset = () => { clearInterval(timer); tl.innerHTML = ""; i = 0; document.querySelectorAll(".node").forEach(n => { n.className = "node"; n.querySelector("span").textContent = "–"; }); };
    const run = () => { reset(); if (!r.events.length) { tl.innerHTML = `<div class="empty">Nothing noteworthy observed.</div>`; return; } timer = setInterval(() => { if (my !== seq || i >= r.events.length) return clearInterval(timer); add(r.events[i++]); }, 650); };
    $("#rp").onclick = run; $("#sk").onclick = () => { clearInterval(timer); while (i < r.events.length) add(r.events[i++]); };
    run(); alerts(r, my);
  }
  function alerts(r, my) {
    const box = $("#als"); if (!r.alerts.length) return;
    box.innerHTML = `<h2>Alert evidence &amp; explanation</h2>` + r.alerts.map((a, k) => `<div class="card" style="margin-bottom:10px"><div class="row sb"><b>${esc(a.evidence.event_type)} <span class="tag ${a.evidence.risk_tier === "WARN" ? "warn" : "bad"}">${esc(a.evidence.risk_tier)}</span></b><span class="sub">${esc(a.evidence.entity.value)} · score ${a.evidence.score.toFixed(2)}</span></div>${a.escalated_from && a.escalated_from.length > 1 ? `<div class="sub">Escalated ${a.escalated_from.map(esc).join(" → ")} as more evidence arrived; showing the latest alert.</div>` : ""}
    <ul class="plain">${a.evidence.reasons.map(x => `<li class="sub">${esc(x)}</li>`).join("")}</ul><div class="expl" id="ne${k}" style="margin-top:8px">${esc(a.advice.text)} <span class="tag">template</span></div></div>`).join("");
    if (!r.llama_available) return;
    const tok = cur.tok = Math.random();
    (async () => {
      for (let k = 0; k < r.alerts.length; k++) {
        const b = $("#ne" + k); if (!b || my !== seq || cur.tok !== tok) return;
        b.className = "expl loading"; b.innerHTML = `<span class="spin"></span>Llama is writing an explanation…`;
        try { const a = await api("/api/sensor/explain", { evidence: r.alerts[k].evidence }); if (my !== seq || cur.tok !== tok) return;
          b.className = "expl"; b.innerHTML = `${esc(a.text)} <span class="tag ${a.source === "llama" ? "llama" : ""}">${a.source === "llama" ? "Llama 3.2 · verified" : "Built-in template"}</span> <span class="sub">verifier: ${esc(a.verifier)}${a.llm_seconds ? " · " + a.llm_seconds + " s" : ""}${a.llm_stats && a.llm_stats.decode_tok_s ? " · " + a.llm_stats.decode_tok_s + " tok/s" : ""}</span>${a.source === "template" && a.llm_raw ? `<p class="sub" style="margin:6px 0 0">The Llama draft failed verification, so the deterministic text is shown.</p><details class="sub"><summary>Show rejected Llama draft</summary><div class="msg">${esc(a.llm_raw)}</div></details>` : ""}`;
        } catch (e) { b.className = "expl"; b.textContent = r.alerts[k].advice.text; }
      }
    })();
  }
}

/* ---------- Live System Metrics ---------- */
function pgSystem() {
  $("#main").innerHTML = `<h1>Live System Metrics</h1><p class="lede">Everything on this page is read or measured on this machine, right now. Nothing is hard-coded or copied from earlier runs.</p><div id="sys"><span class="spin"></span></div>`;
  const my = seq; let timer;
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
    if (my !== seq) return;
    $("#sys").innerHTML = `<div id="live"></div>
    <h2>AI models &amp; runtime files</h2><div class="card"><p class="sub" style="margin:0 0 10px">The SHA-256 is a fingerprint of each file. If even one byte changes, it changes — so matching the organiser's reference values proves these are the exact models that were approved.</p>
    <table><thead><tr><th>Artifact</th><th>Size</th><th>SHA-256</th></tr></thead><tbody id="mf">${s.models.map(mrow).join("")}</tbody></table></div>
    <div class="row sb"><h2>Measured performance</h2><button class="sm ghost" id="rb" style="margin-top:18px">↻ Re-measure</button></div>
    <div class="card" id="bo"></div>`;
    live(s); timer = setInterval(async () => { if (my !== seq) return clearInterval(timer); try { live(await api("/api/system")); } catch { } }, 3000);
    api("/api/system/hashes").then(m => { if (my === seq) $("#mf").innerHTML = m.map(mrow).join(""); });
    const measure = async () => {
      $("#rb").disabled = true; $("#bo").innerHTML = `<span class="spin"></span>Measuring detector and network sensor…`;
      try {
        const r = await api("/api/system/benchmark", {}); if (my !== seq) return;
        const base = kv({
          "SMS detector — median": [r.detector_p50_ms + " ms", `Typical time to decide whether one message is a scam (${r.detector_samples} runs).`],
          "SMS detector — slowest 5%": [r.detector_p95_ms + " ms", "95% of messages are decided at least this fast."],
          "Network sensor replay": [r.sensor_replay_ms + " ms", "Time to replay and analyse a full SMS → DNS → beacon capture."],
        });
        $("#bo").innerHTML = base + `<div id="lb" style="margin-top:6px"><span class="spin"></span>Measuring Llama (one real explanation, a few seconds)…</div>`;
        if (s.llama_ready) {
          const l = await api("/api/system/llama-benchmark", {}); if (my !== seq) return; const st = l.stats || {};
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
    $("#rb").onclick = measure; measure();
  }).catch(e => $("#sys").innerHTML = `<div class="err">${esc(e.message)}</div>`);
}

status(); route();
