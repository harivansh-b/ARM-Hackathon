"""Terminal interface: ./guardian {serve,check,import,sensor,system}"""
from __future__ import annotations

import argparse, json, sys
from pathlib import Path

from . import core

C = {"ALERT": "\033[31m", "REVIEW": "\033[33m", "BENIGN_CANDIDATE": "\033[32m", "ALERTS": "\033[31m", "CLEAN": "\033[32m"}
R = "\033[0m"


def col(s: str, key: str | None = None) -> str:
    return f"{C.get(key or s, '')}{s}{R}" if sys.stdout.isatty() else s


def cmd_check(a):
    text = " ".join(a.text) if a.text else sys.stdin.read()
    r = core.check_message(text, a.sender, with_llm=not a.no_llm)
    if a.json:
        return print(json.dumps(r, indent=2, ensure_ascii=False))
    print(f"Verdict   {col(r['state'])}  ({r['risk_tier']}, score {r['score']:.3f}, {r['latency_ms']} ms)")
    for s in r["signals"]:
        print(f"  • {s['signal']}: {s['matched']}")
    for u in r["urls"]:
        print(f"  URL {u['domain']} [{u['tier']}] {'; '.join(u['reasons'])}")
    print(f"Explanation ({r['advice']['source']}, verifier: {r['advice']['verifier']})\n  {r['advice']['text']}")
    if r["actions"]:
        print("Approved actions")
        for x in r["actions"]:
            print(f"  ✔ {x}")


def cmd_import(a):
    r = core.import_messages(Path(a.file))
    if a.json:
        return print(json.dumps(r, indent=2, ensure_ascii=False))
    print(f"{r['total']} messages in {r['elapsed_ms']} ms — " + ", ".join(f"{k}: {v}" for k, v in r["counts"].items()))
    for row in r["rows"][: a.top]:
        print(f"[{col(row['state']):>16}] {row['score']:.3f}  {row['sender'] or '-':<14} {row['text'][:80]!r}")


def cmd_sensor(a):
    if a.list or not a.scenario:
        for s in core.list_scenarios():
            print(f"{s['id']:<20} {s['title']}")
        return
    r = core.replay(a.scenario if not Path(a.scenario).exists() else None, pcap=Path(a.scenario) if Path(a.scenario).exists() else None, with_llm=a.llm)
    if a.json:
        return print(json.dumps(r, indent=2, ensure_ascii=False))
    print(f"{r['title']} — {r['packets']} packets, {col(r['verdict'])}")
    for e in r["events"]:
        print(f"  +{e['t']:7.2f}s  {e['layer']:<5} {e['title']}\n             {e['detail']}")
    for al in r["alerts"]:
        print(f"Alert {al['evidence']['event_type']}: {al['advice']['text']}  [{al['advice']['source']}]")


def cmd_system(a):
    s = core.system_info()
    print(f"{s['arch']} · {s['cpus']} CPUs · {s['mem_mb']} MB · kernel {s['kernel']} · python {s['python']}")
    print(f"Llama runner: {'ready' if s['llama_ready'] else 'NOT FOUND'}")
    for m in core.model_files(hashes=True):
        print(f"  {'ok ' if m['present'] else 'MISSING'} {m['path']:<42} {m['sha256'] or '-'}")
    if a.bench:
        print(json.dumps(core.live_benchmark(), indent=2))
        if a.llm:
            print(json.dumps(core.llama_benchmark(), indent=2))


def main():
    p = argparse.ArgumentParser(prog="guardian", description="Guardian offline security assistant")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="start the web UI"); s.add_argument("--host", default="0.0.0.0"); s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=lambda a: __import__("guardian_web.server", fromlist=["serve"]).serve(a.host, a.port))
    s = sub.add_parser("check", help="check one message (text args or stdin)"); s.add_argument("text", nargs="*"); s.add_argument("--sender")
    s.add_argument("--no-llm", action="store_true"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_check)
    s = sub.add_parser("import", help="scan a CSV/XML/JSON/TXT file"); s.add_argument("file"); s.add_argument("--top", type=int, default=25)
    s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_import)
    s = sub.add_parser("sensor", help="replay a scenario or .pcap"); s.add_argument("scenario", nargs="?"); s.add_argument("--list", action="store_true")
    s.add_argument("--llm", action="store_true"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_sensor)
    s = sub.add_parser("system", help="offline status, hashes, benchmarks"); s.add_argument("--bench", action="store_true"); s.add_argument("--llm", action="store_true")
    s.set_defaults(fn=cmd_system)
    a = p.parse_args()
    try:
        a.fn(a)
    except (ValueError, FileNotFoundError) as e:
        sys.exit(f"guardian: {e}")
