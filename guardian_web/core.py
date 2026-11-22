"""Guardian web/CLI engine. Thin glue over person-a/b/c; no detection logic lives here."""
from __future__ import annotations

import hashlib, json, os, platform, re, shlex, statistics, subprocess, sys, tempfile, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("person-a", "person-b", "person-c"):
    sys.path.insert(0, str(ROOT / p))

from guardian_models.detectors import analyze_url  # noqa: E402
from guardian_models.evidence_graph import correlate  # noqa: E402
from guardian_models.normalize import registrable_domain  # noqa: E402
from guardian_models.runtime import SMSRuntime  # noqa: E402
from guardian_models.safety import approved_actions  # noqa: E402
from guardian_app.advisor import LlamaRunner, explain, template_explanation  # noqa: E402
from guardian_app.importers import load_messages  # noqa: E402
from guardian_net.cli import replay_pcap  # noqa: E402
from guardian_net.dnswire import DNSMessage  # noqa: E402
from guardian_net.pcapio import PcapReader  # noqa: E402
from guardian_net.tls_hello import parse_client_hello  # noqa: E402

LLAMA_DIR = ROOT / "runtime" / "executorch"
LLAMA_BIN = LLAMA_DIR / "llama_main"
LLAMA_LIB = LLAMA_DIR / "libllama_runner.so"
LLAMA_MODEL = ROOT / "models" / "llama" / "llama3_2.pte"
LLAMA_TOK = ROOT / "models" / "llama" / "tokenizer.model"
SMS_ARTIFACT = ROOT / "person-c" / "artifacts" / "sms.json"
SCEN_DIR = ROOT / "person-b" / "eval" / "scenarios"
SAMPLE_CSV = ROOT / "person-a" / "samples" / "sms.csv"

os.environ["LD_LIBRARY_PATH"] = f"{LLAMA_DIR}:{os.environ.get('LD_LIBRARY_PATH', '')}"


def llama_command() -> str:
    env = os.environ.get("GUARDIAN_LLAMA_CMD")
    if env:
        return env
    if not (LLAMA_BIN.exists() and LLAMA_MODEL.exists() and LLAMA_TOK.exists()):
        return ""
    return (f"{shlex.quote(str(LLAMA_BIN))} --model_path {shlex.quote(str(LLAMA_MODEL))} "
            f"--tokenizer_path {shlex.quote(str(LLAMA_TOK))} --temperature 0 --seq_len 512 "
            "--max_new_tokens 128 --prompt {prompt}")


_runtime: SMSRuntime | None = None
_runner: LlamaRunner | None = None
_llm_lock = threading.Lock()


def sms_runtime() -> SMSRuntime:
    global _runtime
    if _runtime is None:
        if not SMS_ARTIFACT.exists():
            train_sms_model()
        _runtime = SMSRuntime.from_artifact(SMS_ARTIFACT)
    return _runtime


def train_sms_model() -> None:
    """One-time local training, same steps as guardian_sms_pipeline.sh."""
    c = ROOT / "person-c"
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        prep = tmp.name
    try:
        subprocess.run([sys.executable, str(c / "tools" / "prepare_sms_dataset.py"), prep,
                        str(c / "data" / "public_sms.jsonl"), str(c / "data" / "sms_multilingual.jsonl")],
                       check=True, capture_output=True)
        SMS_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([sys.executable, "-m", "guardian_models.train_sms", prep, "artifacts/sms.json"],
                       cwd=c, check=True, capture_output=True)
    finally:
        os.unlink(prep)


def runner() -> LlamaRunner:
    global _runner
    if _runner is None:
        _runner = LlamaRunner(llama_command())
    return _runner


def llama_ready() -> bool:
    return runner().available


# ---------------------------------------------------------------- SMS
def check_message(text: str, sender: str | None = None, with_llm: bool = False) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("message is empty")
    ev = sms_runtime().analyze(text, sender=sender or None)
    flagged = ev["decision_state"] in ("ALERT", "REVIEW")
    urls = [analyze_url(u) for u in ev["extracted_urls"][:3]]
    links = correlate([ev] + urls) if flagged and urls else []
    if flagged and with_llm and llama_ready():
        with _llm_lock:
            advice = explain(ev, runner())
    elif flagged:
        advice = {"text": template_explanation(ev), "source": "template", "verifier": "llm not requested"}
    else:
        advice = {"text": "No strong scam signal found. This is not a guarantee of safety.",
                  "source": "template", "verifier": "n/a"}
    return {
        "state": ev["decision_state"], "risk_tier": ev["risk_tier"], "score": ev["score"],
        "language": ev.get("language_label"), "latency_ms": ev["latency_ms"],
        "signals": [{"signal": s["signal"], "matched": s["matched_text"]} for s in ev["matched_signals"]],
        "reasons": ev["reasons"], "model_evidence": ev.get("model_evidence", [])[:6],
        "urls": [{"url": u["normalized_url"], "domain": u["entity"]["value"], "tier": u["risk_tier"],
                  "score": u["score"], "reasons": u["reasons"]} for u in urls],
        "story": [{"from": l.source_id, "to": l.target_id, "relation": l.relation} for l in links],
        "actions": approved_actions(ev) if flagged else [],
        "advice": advice, "flagged": flagged, "llama_available": llama_ready(),
    }


def import_messages(path: Path, limit: int = 2000) -> dict:
    return analyze_batch(load_messages(path)[:limit])


SCAM_LABELS = {"1", "scam", "spam", "smish", "smishing", "phish", "phishing", "fraud", "malicious"}
HAM_LABELS = {"0", "ham", "legit", "legitimate", "benign", "normal", "safe"}


def _label(v) -> int | None:
    s = str(v).strip().lower() if v is not None else ""
    return 1 if s in SCAM_LABELS else 0 if s in HAM_LABELS else None


def analyze_batch(msgs: list[dict]) -> dict:
    rt = sms_runtime()
    rows, counts = [], {"ALERT": 0, "REVIEW": 0, "BENIGN_CANDIDATE": 0}
    cm = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    t0 = time.perf_counter()
    for m in msgs:
        ev = rt.analyze(m["text"], sender=m.get("sender"))
        counts[ev["decision_state"]] = counts.get(ev["decision_state"], 0) + 1
        flagged = ev["decision_state"] in ("ALERT", "REVIEW")
        lab = _label(m.get("label"))
        correct = None if lab is None else (flagged == bool(lab))
        if lab is not None:
            cm[("tp" if flagged else "fn") if lab else ("fp" if flagged else "tn")] += 1
        rows.append({"id": m["id"], "sender": m.get("sender"), "text": m["text"], "state": ev["decision_state"],
                     "risk_tier": ev["risk_tier"], "score": ev["score"], "label": None if lab is None else ("scam" if lab else "ham"), "correct": correct,
                     "signals": [s["signal"] for s in ev["matched_signals"]], "urls": ev["extracted_urls"],
                     "actions": approved_actions(ev) if flagged else [],
                     "explanation": template_explanation(ev) if flagged else ""})
    rows.sort(key=lambda r: ({"ALERT": 0, "REVIEW": 1}.get(r["state"], 2), -r["score"]))
    out = {"total": len(rows), "counts": counts, "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1), "rows": rows}
    n = sum(cm.values())
    if n:
        sc = cm["tp"] + cm["fn"]; hm = cm["tn"] + cm["fp"]
        out["eval"] = {**cm, "labelled": n, "accuracy": round((cm["tp"] + cm["tn"]) / n, 3), "scams": sc, "hams": hm,
                       "recall": round(cm["tp"] / sc, 3) if sc else None, "false_alarm_rate": round(cm["fp"] / hm, 3) if hm else None,
                       "note": "A message counts as flagged if the verdict is Scam likely or Needs review."}
    return out


# ---------------------------------------------------------------- Network
SCENARIOS = {
    "smishing_c2_chain": {"title": "Smishing → C2 beacon", "blurb": "Phishing SMS link resolves via DNS, then the host beacons every 5 s.",
                          "sms": "HDFC Bank: your account will be blocked today. Update KYC immediately at http://phish-bank.test/verify"},
    "dns_tunnel": {"title": "DNS tunnelling", "blurb": "High-entropy TXT queries encode data in subdomains."},
    "port_scan": {"title": "Outbound port scan", "blurb": "One host sweeps ports 20–41 with SYN probes."},
    "exfil_spike": {"title": "Exfiltration spike", "blurb": "Small normal flows, then a 200 KB burst to one destination."},
    "benign_linux": {"title": "Benign Linux baseline", "blurb": "Ordinary system traffic; must raise no alerts."},
}


def list_scenarios() -> list[dict]:
    return [{"id": k, "file": f"{k}.pcap", **v, "available": (SCEN_DIR / f"{k}.pcap").exists(), "has_sms": "sms" in v} for k, v in SCENARIOS.items()]


def reg(host: str) -> str:
    """Registrable-domain approximation on bare hostnames (same rule as Person C, which expects URLs)."""
    labels = (host or "").strip(".").lower().split(".")
    if len(labels) < 2 or all(l.isdigit() for l in labels):
        return host or ""
    return ".".join(labels[-2:])


def _pcap_events(path: Path) -> tuple[list[dict], int, float]:
    """Observable layer events from the capture: DNS, TLS SNI, connection groups."""
    events, seen_dns, conns, n = [], {}, {}, 0
    t0 = None
    with PcapReader(path) as rd:
        for pkt in rd.parsed_packets():
            n += 1
            t0 = pkt.timestamp if t0 is None else t0
            if pkt.proto == "UDP" and 53 in (pkt.src_port, pkt.dst_port):
                try:
                    m = DNSMessage.parse(pkt.payload)
                except Exception:
                    continue
                if not m.questions:
                    continue
                q = reg(m.first_question_name)
                d = seen_dns.setdefault(q, {"layer": "DNS", "ts": pkt.timestamp, "key": q, "count": 0, "ips": []})
                if m.is_response:
                    d["ips"] += [str(a.rdata) for a in m.answers if isinstance(a.rdata, str) and re.match(r"^\d+\.\d+\.\d+\.\d+$", a.rdata)]
                else:
                    d["count"] += 1
            elif pkt.proto == "TCP":
                if pkt.is_syn:
                    c = conns.setdefault((pkt.src_ip, pkt.dst_ip), {"layer": "CONN", "ts": pkt.timestamp, "last": pkt.timestamp,
                                                                  "n": 0, "ports": set(), "times": []})
                    c["n"] += 1; c["last"] = pkt.timestamp; c["ports"].add(pkt.dst_port); c["times"].append(pkt.timestamp)
                if pkt.payload[:1] == b"\x16":
                    try:
                        h = parse_client_hello(pkt.payload)
                    except Exception:
                        h = None
                    if h and h.sni:
                        k = (pkt.dst_ip, h.sni)
                        if k not in seen_dns:
                            seen_dns[k] = {"layer": "TLS", "ts": pkt.timestamp, "key": h.sni, "dst": pkt.dst_ip, "count": 0}
                        seen_dns[k]["count"] += 1
    for d in seen_dns.values():
        if d["layer"] == "DNS":
            ips = sorted(set(d["ips"]))
            events.append({"layer": "DNS", "ts": d["ts"], "title": f"DNS lookups: {d['key']}" if d["count"] > 1 else f"DNS lookup: {d['key']}",
                           "detail": f"{d['count']} quer{'y' if d['count'] == 1 else 'ies'}" + (f" → {', '.join(ips)}" if ips else ""), "entity": d["key"], "ips": ips})
        else:
            events.append({"layer": "TLS", "ts": d["ts"], "title": f"TLS handshake: {d['key']}",
                           "detail": f"{d['count']} ClientHello(s) to {d['dst']}", "entity": d["key"]})
    for (src, dst), c in conns.items():
        gaps = [b - a for a, b in zip(c["times"], c["times"][1:])]
        cadence = f", every {statistics.mean(gaps):.1f}s" if len(gaps) >= 3 and statistics.pstdev(gaps) < 0.5 else ""
        ports = sorted(c["ports"])
        pt = f"port {ports[0]}" if len(ports) == 1 else f"{len(ports)} ports ({ports[0]}–{ports[-1]})"
        events.append({"layer": "CONN", "ts": c["ts"], "title": f"{c['n']} TCP connection{'s' if c['n'] != 1 else ''} {src} → {dst}",
                       "detail": f"{pt}{cadence}", "entity": dst})
    return events, n, (t0 or 0.0)


def replay(scenario: str | None = None, pcap: Path | None = None, with_llm: bool = False) -> dict:
    if scenario:
        if scenario not in SCENARIOS or not (SCEN_DIR / f"{scenario}.pcap").exists():
            raise ValueError("unknown scenario")
        pcap = SCEN_DIR / f"{scenario}.pcap"
    assert pcap
    t_start = time.perf_counter()
    raw_alerts = replay_pcap(pcap, silent=True)
    merged: dict = {}
    for a in raw_alerts:  # the aggregator re-alerts when risk escalates; keep the latest per (type, entity)
        k = (a["event_type"], a["entity"]["value"])
        if k not in merged:
            merged[k] = {"final": a, "tiers": [a["risk_tier"]]}
        else:
            if a["risk_tier"] not in merged[k]["tiers"]:
                merged[k]["tiers"].append(a["risk_tier"])
            if a["score"] >= merged[k]["final"]["score"]:
                merged[k]["final"] = a
    alerts = [m["final"] for m in merged.values()]
    tiers = {k: m["tiers"] for k, m in merged.items()}
    tkey = lambda a: (a["event_type"], a["entity"]["value"])
    source = str(Path(pcap).relative_to(ROOT)) if scenario else "uploaded file"
    events, npk, t0 = _pcap_events(pcap)
    meta = SCENARIOS.get(scenario or "", {})
    sms_ev = url_ev = None
    if meta.get("sms"):
        sms_res = check_message(meta["sms"], sender="VM-HDFCBK")
        sms_ev = sms_res
        first_ts = min([e["ts"] for e in events] + [a["timestamp"] for a in alerts] or [t0])
        events.append({"layer": "SMS", "ts": first_ts - 0.2, "scenario_input": True, "title": f"SMS received → {sms_res['state']}",
                       "detail": f"{sms_res['risk_tier']} · score {sms_res['score']:.2f} · " + ", ".join(s["signal"] for s in sms_res["signals"][:3]),
                       "entity": None})
        for u in sms_res["urls"]:
            events.append({"layer": "URL", "ts": first_ts - 0.1, "scenario_input": True, "title": f"URL extracted: {u['domain']}",
                           "detail": f"{u['tier']} · " + ("; ".join(u["reasons"]) or "no structural flags"), "entity": u["domain"]})
            url_ev = u
    for a in alerts:
        events.append({"layer": "ALERT", "ts": float(a["timestamp"]), "title": f"{a['event_type']} · {a['risk_tier']}",
                       "detail": (f"escalated {' → '.join(tiers[tkey(a)])}; " if len(tiers[tkey(a)]) > 1 else "") + "; ".join(a["reasons"])[:200],
                       "entity": a["entity"]["value"], "alert_id": a["evidence_id"]})
    events.sort(key=lambda e: e["ts"])
    base = events[0]["ts"] if events else t0
    for e in events:
        e["t"] = round(e["ts"] - base, 2)
    # cross-layer links (SMS→URL→DNS→connection→alert)
    links = []
    by = lambda layer: [i for i, e in enumerate(events) if e["layer"] == layer]
    for i in by("SMS"):
        for j in by("URL"): links.append([i, j, "contains_url"])
    for j in by("URL"):
        for k in by("DNS"):
            if reg(events[j]["entity"]) == reg(events[k]["entity"]): links.append([j, k, "queried_domain"])
    for k in by("DNS"):
        for c in by("CONN") + by("ALERT"):
            if events[c]["entity"] in events[k].get("ips", []) or (events[c]["layer"] == "CONN" and events[c]["entity"] in events[k].get("ips", [])):
                links.append([k, c, "resolved_ip"])
    for c in by("CONN"):
        for a in by("ALERT"):
            if str(events[a]["entity"]) == events[c]["entity"] and not any(l[1] == a for l in links if l[0] in by("DNS")): links.append([c, a, "flagged_as"])
    alert_rows = []
    for a in alerts:
        alert_rows.append({"evidence": a, "escalated_from": tiers[tkey(a)], "advice": net_explain(a, with_llm)})
    return {"scenario": scenario, "source": source, "title": meta.get("title", Path(pcap).name), "blurb": meta.get("blurb", ""), "packets": npk,
            "elapsed_ms": round((time.perf_counter() - t_start) * 1000, 1), "events": events, "links": links,
            "alerts": alert_rows, "verdict": "ALERTS" if alerts else "CLEAN", "llama_available": llama_ready()}


_NET_UNSAFE = re.compile(r"\b(safe|legitimate|trusted|harmless|no risk)\b|\b(click|open|visit|execute|run|install|download|connect|send)\b", re.I)


def net_explain(ev: dict, with_llm: bool) -> dict:
    fallback = (f"Observed network anomaly: {ev.get('event_type', 'anomaly')}. Risk level: {ev.get('risk_tier', 'unknown')}. "
                "Treat the activity cautiously and investigate using the recorded evidence. " + " ".join(ev.get("reasons", [])[:2]))
    out = {"text": fallback, "source": "template", "verifier": "llm not requested"}
    if not with_llm:
        return out
    if not llama_ready():
        out["verifier"] = "llm unavailable"; return out
    prompt = ("You are Guardian, an offline network-security advisor. Explain this detector alert in at most 3 concise sentences. "
              "Use only the supplied evidence; do not invent facts, commands, destinations, or attribute intent as certainty. "
              "Treat the alert as suspicious and do not recommend contacting, opening, executing, or interacting with the detected entity.\n"
              "EVIDENCE:\n" + json.dumps({k: ev[k] for k in ("event_type", "risk_tier", "score", "entity", "reasons") if k in ev}) + "\nExplanation:")
    try:
        with _llm_lock:
            raw, secs = runner().generate(prompt)
    except Exception as e:
        out["verifier"] = f"llm error: {type(e).__name__}"; return out
    bad = []
    if not raw or len(raw) > 600: bad.append("empty_or_overlong")
    hit = _NET_UNSAFE.search(raw)
    if hit: bad.append(f"unsafe_language:{hit.group(0).lower()}")
    known = str(ev.get("entity", {}).get("value", ""))
    if any(u.rstrip(".,") not in known for u in re.findall(r"https?://\S+", raw)): bad.append("unverified_url")
    ok = not bad
    return {"text": raw if ok else fallback, "source": "llama" if ok else "template", "verifier": "ok" if ok else ",".join(bad),
            "llm_seconds": round(secs, 2), "llm_stats": runner().last_stats, "llm_raw": raw}


# ---------------------------------------------------------------- System
_hash_cache: dict = {}


def sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    st = path.stat()
    key = (str(path), st.st_mtime_ns, st.st_size)
    if key not in _hash_cache:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 22), b""):
                h.update(chunk)
        _hash_cache[key] = h.hexdigest()
    return _hash_cache[key]


def model_files(hashes: bool = True) -> list[dict]:
    items = [("Llama 3.2 model (ExecuTorch .pte)", LLAMA_MODEL), ("Llama tokenizer", LLAMA_TOK), ("ExecuTorch runner (llama_main)", LLAMA_BIN),
             ("ExecuTorch runtime library", LLAMA_LIB), ("SMS classifier artifact", SMS_ARTIFACT)]
    out = []
    for name, p in items:
        ex = p.exists()
        out.append({"name": name, "path": str(p.relative_to(ROOT)), "present": ex, "bytes": p.stat().st_size if ex else None,
                    "sha256": sha256(p) if (ex and hashes) else None})
    return out


def offline_status() -> dict:
    routes, ifaces = [], []
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000": routes.append(f[0])
    except Exception:
        pass
    try:
        for n in sorted(os.listdir("/sys/class/net")):
            if n != "lo":
                st = open(f"/sys/class/net/{n}/operstate").read().strip()
                ifaces.append({"name": n, "state": st})
    except Exception:
        pass
    return {"default_route": bool(routes), "interfaces": ifaces,
            "note": "Guardian makes no outbound requests: detection, Llama inference and replay are all local. "
                    "The interface list is informational (a forwarded VM port needs a NIC)."}


def live_benchmark(n: int = 200) -> dict:
    rt = sms_runtime()
    msgs = [m["text"] for m in load_messages(SAMPLE_CSV)]
    rt.analyze(msgs[0])
    ms = sorted(rt.analyze(msgs[i % len(msgs)])["latency_ms"] for i in range(n))
    pk = sorted(ms)
    res = {"detector_samples": n, "detector_p50_ms": round(statistics.median(ms), 4), "detector_p95_ms": round(pk[int(0.95 * n) - 1], 4)}
    t = time.perf_counter(); replay("smishing_c2_chain"); res["sensor_replay_ms"] = round((time.perf_counter() - t) * 1000, 1)
    try:
        import resource; res["process_peak_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    except Exception:
        pass
    return res


def llama_benchmark() -> dict:
    if not llama_ready():
        return {"available": False, "note": "Llama runner not found."}
    ev = sms_runtime().analyze("Dear customer your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.top/login")
    with _llm_lock:
        r = explain(ev, runner())
    try:
        import resource; child = round(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024, 1)
    except Exception:
        child = None
    return {"available": True, "child_peak_rss_mb": child, "wall_seconds": r.get("llm_seconds"), "source": r["source"], "verifier": r["verifier"], "stats": r.get("llm_stats", {}),
            "raw_output": r.get("llm_raw", "")[:300]}


def stored_benchmarks() -> list[dict]:
    out = []
    for rel, label in [("integration-tests/phase2_detector_perf.json", "Detector latency (recorded)"),
                       ("integration-tests/phase3_advisor_benchmark.json", "Llama advisor (recorded)"),
                       ("integration-tests/phase4_network_sensor_benchmark.json", "Network sensor (recorded)")]:
        p = ROOT / rel
        if p.exists():
            try:
                d = json.loads(p.read_text())
                out.append({"label": label, "file": rel, "data": d})
            except Exception:
                pass
    return out


SERVER_PORT = 0


def own_outbound_connections() -> int:
    """Established TCP sockets owned by this process that it did NOT accept (i.e. it dialled out)."""
    inodes = set()
    try:
        for fd in os.listdir("/proc/self/fd"):
            try:
                t = os.readlink(f"/proc/self/fd/{fd}")
                if t.startswith("socket:["):
                    inodes.add(t[8:-1])
            except OSError:
                pass
    except OSError:
        return 0
    n = 0
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            for line in open(f).read().splitlines()[1:]:
                p = line.split()
                if p[3] == "01" and p[9] in inodes and int(p[1].rsplit(":", 1)[1], 16) != SERVER_PORT:
                    n += 1
        except OSError:
            pass
    return n


def _meminfo() -> dict:
    d = {}
    try:
        for l in open("/proc/meminfo"):
            k, v = l.split(":", 1); d[k] = int(v.split()[0]) / 1024
    except Exception:
        pass
    return d


def system_info() -> dict:
    cpu = ""
    try:
        cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.lower().startswith(("model name", "hardware"))), "")
    except Exception:
        pass
    if not cpu:
        try:
            out = subprocess.run(["lscpu"], capture_output=True, text=True, timeout=3).stdout
            cpu = next((l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("Model name")), "")
        except Exception:
            pass
    m = _meminfo()
    temp = None
    try:
        temp = round(int(open("/sys/class/thermal/thermal_zone0/temp").read()) / 1000, 1)
    except Exception:
        pass
    up = load = None
    try:
        up = int(float(open("/proc/uptime").read().split()[0])); load = [round(x, 2) for x in os.getloadavg()]
    except Exception:
        pass
    try:
        import resource; rss = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    except Exception:
        rss = None
    return {"arch": platform.machine(), "kernel": platform.release(), "python": platform.python_version(), "cpus": os.cpu_count(),
            "cpu": cpu, "mem_mb": round(m.get("MemTotal", 0)) or None, "mem_available_mb": round(m.get("MemAvailable", 0)) or None,
            "load": load, "uptime_s": up, "cpu_temp_c": temp, "guardian_rss_mb": rss,
            "outbound_connections": own_outbound_connections(), "server_port": SERVER_PORT,
            "llama_ready": llama_ready(), "offline": offline_status(), "models": model_files(hashes=False),
            "arm64": platform.machine() in ("aarch64", "arm64")}


# ---------------------------------------------------------------- Sustained run
def _cpu_times() -> tuple[float, float]:
    try:
        f = [float(x) for x in open("/proc/stat").readline().split()[1:]]
        return sum(f), f[3] + (f[4] if len(f) > 4 else 0)  # total, idle+iowait
    except Exception:
        return 0.0, 0.0


def _rss_mb() -> float | None:
    try:
        return round(int(open("/proc/self/statm").read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1048576, 1)
    except Exception:
        return None


def _temp_c() -> float | None:
    try:
        return round(int(open("/sys/class/thermal/thermal_zone0/temp").read()) / 1000, 1)
    except Exception:
        return None


def _pctl(vals: list, p: float):
    v = sorted(x for x in vals if x is not None)
    return v[min(len(v) - 1, int(p * len(v)))] if v else None


class SustainedRun:
    """Continuous detector + sensor load in a background thread, sampled every ~2 s. One run at a time."""
    WINDOW_S, MAX_SECONDS, LLAMA_EVERY = 2.0, 1800, 5

    def __init__(self) -> None:
        self.lock, self.thread, self.stop_ev = threading.Lock(), None, threading.Event()
        self._reset()

    def _reset(self) -> None:
        self.samples, self.running, self.started, self.ended, self.llama, self.error = [], False, None, None, False, None

    def start(self, llama: bool) -> None:
        with self.lock:
            if self.running:
                raise ValueError("a sustained run is already in progress")
            self._reset()
            self.llama, self.running, self.started = bool(llama) and llama_ready(), True, time.time()
            self.stop_ev.clear()
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()

    def stop(self) -> None:
        self.stop_ev.set()
        if self.thread:
            self.thread.join(timeout=8)

    def _texts(self) -> list[str]:
        texts = [m["text"] for m in load_messages(SAMPLE_CSV)]
        extra = ROOT / "person-a" / "eval" / "extra_samples.jsonl"
        try:
            texts += [json.loads(l)["text"] for l in extra.read_text(encoding="utf8").splitlines() if l.strip()]
        except Exception:
            pass
        return texts

    def _loop(self) -> None:
        try:
            rt, texts, i, tick = sms_runtime(), self._texts(), 0, 0
            total0, idle0 = _cpu_times()
            while not self.stop_ev.is_set() and time.time() - self.started < self.MAX_SECONDS:
                t0 = time.perf_counter(); lat, ops = [], 0
                while time.perf_counter() - t0 < self.WINDOW_S and not self.stop_ev.is_set():
                    lat.append(rt.analyze(texts[i % len(texts)])["latency_ms"]); i += 1; ops += 1
                    if i % 500 == 0:
                        replay("smishing_c2_chain")
                wall = max(time.perf_counter() - t0, 1e-6)
                total1, idle1 = _cpu_times()
                cpu = round(100 * (1 - (idle1 - idle0) / (total1 - total0)), 1) if total1 > total0 else None
                total0, idle0 = total1, idle1
                mem = _meminfo()
                s = {"t": round(time.time() - self.started, 1), "ops_per_s": round(ops / wall), "lat_p50_ms": round(_pctl(lat, .5) or 0, 3),
                     "lat_p95_ms": round(_pctl(lat, .95) or 0, 3),
                     "mem_used_mb": round(mem.get("MemTotal", 0) - mem.get("MemAvailable", 0)) if mem else None, "rss_mb": _rss_mb(),
                     "sys_cpu_pct": cpu, "load1": round(os.getloadavg()[0], 2), "temp_c": _temp_c(), "llama_s": None, "llama_tok_s": None}
                tick += 1
                if self.llama and tick % self.LLAMA_EVERY == 0 and not self.stop_ev.is_set():
                    ev = rt.analyze(texts[0])
                    with _llm_lock:
                        r = explain(ev, runner())
                    s["llama_s"] = r.get("llm_seconds"); s["llama_tok_s"] = (r.get("llm_stats") or {}).get("decode_tok_s")
                self.samples.append(s)
                if len(self.samples) >= 1800:
                    break
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"
        finally:
            self.ended, self.running = time.time(), False

    def summary(self) -> dict | None:
        S = self.samples
        if len(S) < 2:
            return None
        col = lambda k: [s[k] for s in S if s.get(k) is not None]
        ops = col("ops_per_s"); n = max(1, len(ops) // 5)
        head, tail = sum(ops[:n]) / n, sum(ops[-n:]) / n
        first, last = S[0], S[-1]
        temps, ll = col("temp_c"), col("llama_s")
        return {"duration_s": round(last["t"]), "samples": len(S), "total_ops": int(sum(o * self.WINDOW_S for o in ops)),
                "ops_per_s_mean": round(sum(ops) / len(ops)), "ops_per_s_min": min(ops), "ops_per_s_max": max(ops),
                "throughput_drift_pct": round((tail - head) / head * 100, 1) if head else None,
                "lat_p95_ms_worst": max(col("lat_p95_ms")), "mem_used_mb_start": first["mem_used_mb"], "mem_used_mb_end": last["mem_used_mb"],
                "rss_mb_start": first["rss_mb"], "rss_mb_end": last["rss_mb"], "rss_mb_peak": max(col("rss_mb") or [0]),
                "sys_cpu_pct_mean": round(sum(col("sys_cpu_pct")) / len(col("sys_cpu_pct")), 1) if col("sys_cpu_pct") else None,
                "temp_c_start": temps[0] if temps else None, "temp_c_end": temps[-1] if temps else None, "temp_c_max": max(temps) if temps else None,
                "llama_runs": len(ll), "llama_s_mean": round(sum(ll) / len(ll), 2) if ll else None,
                "llama_s_first": ll[0] if ll else None, "llama_s_last": ll[-1] if ll else None}

    def status(self) -> dict:
        el = (self.ended or time.time()) - self.started if self.started else 0
        return {"running": self.running, "llama": self.llama, "elapsed_s": round(el), "max_seconds": self.MAX_SECONDS, "window_s": self.WINDOW_S,
                "has_data": bool(self.samples), "samples": self.samples, "summary": self.summary(), "error": self.error,
                "temp_available": _temp_c() is not None}


SUSTAINED = SustainedRun()
