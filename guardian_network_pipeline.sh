#!/usr/bin/env bash

# Guardian network detection -> local Llama -> verifier -> JSON + metrics

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

PCAP="${1:-$ROOT/person-b/eval/scenarios/smishing_c2_chain.pcap}"
OUT="${2:-$ROOT/guardian_network_report.json}"

RAW="$(mktemp)"
trap 'rm -f "$RAW"' EXIT

if [[ "$PCAP" != /* ]]; then PCAP="$ROOT/$PCAP"; fi
if [[ "$OUT" != /* ]]; then OUT="$ROOT/$OUT"; fi

[[ -f "$PCAP" ]] || { echo "PCAP not found: $PCAP" >&2; exit 2; }

DEFAULT_LLAMA_CMD="/home/dev/executorch/cmake-out/examples/models/llama/llama_main --model_path /home/dev/executorch/llama3_2.pte --tokenizer_path /home/dev/models/llama-3.2-1b-spinquant/tokenizer.model --temperature 0 --seq_len 512 --max_new_tokens 128 --prompt {prompt}"

LLAMA_CMD="${GUARDIAN_LLAMA_CMD:-$DEFAULT_LLAMA_CMD}"
DNS_MODEL="${GUARDIAN_DNS_MODEL:-}"
THREAT_BUNDLE="${GUARDIAN_THREAT_BUNDLE:-}"
BUNDLE_KEY_FILE="${GUARDIAN_BUNDLE_KEY_FILE:-}"

DNS_MODEL="$DNS_MODEL" THREAT_BUNDLE="$THREAT_BUNDLE" BUNDLE_KEY_FILE="$BUNDLE_KEY_FILE" PYTHONPATH="$ROOT/person-b" python3 - "$PCAP" "$RAW" <<'PY'
import sys, json, os
from guardian_net.cli import replay_pcap

alerts = replay_pcap(
    sys.argv[1],
    silent=True,
    dns_model_path=os.environ.get('DNS_MODEL') or None,
    threat_bundle_path=os.environ.get('THREAT_BUNDLE') or None,
    bundle_key_path=os.environ.get('BUNDLE_KEY_FILE') or None,
)

with open(sys.argv[2], "w") as f:
    json.dump(alerts, f)

print(f"Detection stage: {len(alerts)} alert(s)")
PY

ROOT="$ROOT" RAW="$RAW" OUT="$OUT" PCAP="$PCAP" LLAMA_CMD="$LLAMA_CMD" DNS_MODEL="$DNS_MODEL" THREAT_BUNDLE="$THREAT_BUNDLE" BUNDLE_KEY_FILE="$BUNDLE_KEY_FILE" python3 - <<'PY'
import os, json, shlex, subprocess, re, time, platform, resource

root = os.environ["ROOT"]
raw = os.environ["RAW"]
out = os.environ["OUT"]
pcap = os.environ["PCAP"]
cmd = os.environ["LLAMA_CMD"].strip()

alerts = json.load(open(raw))
reports = []

def cpu_temp():
    for p in ['/sys/class/thermal/thermal_zone0/temp',
              '/sys/class/hwmon/hwmon0/temp1_input']:
        try:
            return round(int(open(p).read().strip()) / 1000, 1)
        except Exception:
            pass
    return None

def ram_total_mb():
    try:
        for line in open('/proc/meminfo'):
            if line.startswith('MemTotal:'):
                return round(int(line.split()[1]) / 1024, 1)
    except Exception:
        pass
    return None

def peak_rss_mb():
    try:
        v = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        return round(v / 1024, 1)
    except Exception:
        return None

def parse_stats(s):
    m = re.search(r'PyTorchObserver\s*[:*]?\s*(\{.*\})', s)
    if not m:
        return {}
    try:
        r = json.loads(m.group(1))
    except ValueError:
        return {}

    scale = float(r.get('SCALING_FACTOR_UNITS_PER_SECOND', 1000))
    d = {
        'prompt_tokens': r.get('prompt_tokens'),
        'generated_tokens': r.get('generated_tokens')
    }

    if {'first_token_ms', 'inference_start_ms'} <= r.keys():
        d['ttft_ms'] = round(
            (r['first_token_ms'] - r['inference_start_ms']) * 1000 / scale, 1
        )

    if {'inference_end_ms', 'first_token_ms', 'generated_tokens'} <= r.keys():
        if r['inference_end_ms'] > r['first_token_ms']:
            d['decode_tok_s'] = round(
                r['generated_tokens'] /
                ((r['inference_end_ms'] - r['first_token_ms']) / scale), 2
            )
    return d

for ev in alerts:
    fallback = (
        f"Observed network anomaly: {ev.get('event_type', 'anomaly')}. "
        f"Risk level: {ev.get('risk_tier', 'unknown')}. "
        "Treat the activity cautiously and investigate using the recorded evidence."
    )

    prompt = (
        "You are Guardian, an offline network-security advisor. "
        "Explain this detector alert in at most 3 concise sentences. "
        "Use only the supplied evidence; do not invent facts, commands, destinations, "
        "or attribute intent as certainty. Treat the alert as suspicious and do not "
        "recommend contacting, opening, executing, or interacting with the detected entity.\n"
        "EVIDENCE:\n" + json.dumps(ev, ensure_ascii=False) + "\nExplanation:"
    )

    rawtext = ''
    accepted = False
    reason = 'LLM unavailable; deterministic fallback'
    elapsed = None
    stats = {}
    rc = None
    attempted = bool(cmd and '{prompt}' in cmd)

    started = time.perf_counter()

    if attempted:
        try:
            argv = [
                prompt if x == '{prompt}' else x
                for x in shlex.split(cmd)
            ]

            p = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=90, check=False
            )

            elapsed = round(time.perf_counter() - started, 3)
            rc = p.returncode
            rawtext = p.stdout
            stats = parse_stats(p.stdout + '\n' + p.stderr)

            if prompt in rawtext:
                rawtext = rawtext.split(prompt, 1)[1]

            rawtext = re.split(
                r'PyTorchObserver|<\|eot_id\|>|<\|end_of_text\|>',
                rawtext
            )[0].strip()

            unsafe = re.compile(
                r'\b(safe|legitimate|trusted|harmless|no risk)\b|'
                r'\b(click|open|visit|execute|run|install|download|connect|send)\b',
                re.I
            )

            new_urls = re.findall(r'https?://\S+', rawtext)
            known = str(ev.get('entity', {}).get('value', ''))
            checks = []

            if not rawtext or len(rawtext) > 600:
                checks.append('empty_or_overlong')

            if unsafe.search(rawtext):
                checks.append('unsafe_reassurance_or_action_language')

            if any(u.rstrip('.,') not in known for u in new_urls):
                checks.append('unverified_url')

            if rc:
                checks.append('llm_nonzero_exit')

            accepted = not checks
            reason = 'accepted' if accepted else ','.join(checks)

        except Exception as e:
            elapsed = round(time.perf_counter() - started, 3)
            reason = 'LLM error: ' + type(e).__name__

    reports.append({
        'evidence': ev,
        'llm_raw': rawtext,
        'explanation': rawtext if accepted else fallback,
        'explanation_source': 'llama' if accepted else 'template',
        'verifier': {'accepted': accepted, 'reason': reason},
        'llama_metrics': {
            'attempted': attempted,
            'wall_time_s': elapsed,
            'return_code': rc,
            'observer_metrics': stats,
            'child_peak_rss_mb': peak_rss_mb()
        }
    })

result = {
    'pipeline': 'network_capture_detection_llm_verifier',
    'input_pcap': os.path.abspath(pcap),
    'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'alert_count': len(alerts),
    'alerts': reports,
    'hardware_runtime_metrics': {
        'platform': platform.platform(),
        'architecture': platform.machine(),
        'processor': platform.processor() or None,
        'cpu_count_logical': os.cpu_count(),
        'ram_total_mb': ram_total_mb(),
        'cpu_temperature_c': cpu_temp(),
        'python_version': platform.python_version(),
        'child_peak_rss_mb': peak_rss_mb()
    },
    'llama_summary': {
        'configured': bool(cmd and '{prompt}' in cmd),
        'attempts': sum(x['llama_metrics']['attempted'] for x in reports),
        'accepted': sum(x['verifier']['accepted'] for x in reports),
        'wall_times_s': [
            x['llama_metrics']['wall_time_s']
            for x in reports if x['llama_metrics']['wall_time_s'] is not None
        ],
        'ttft_ms': [
            x['llama_metrics']['observer_metrics'].get('ttft_ms')
            for x in reports if 'ttft_ms' in x['llama_metrics']['observer_metrics']
        ],
        'decode_tok_s': [
            x['llama_metrics']['observer_metrics'].get('decode_tok_s')
            for x in reports if 'decode_tok_s' in x['llama_metrics']['observer_metrics']
        ],
        'note': (
            'ExecuTorch observer TTFT/decode fields only appear if the runner '
            'emits PyTorchObserver metrics. Child peak RSS and wall time are '
            'measured; CPU temperature is best-effort.'
        )
    },
    'note': (
        'PCAP replay, not live capture. Rule-based verifier screening '
        'is not proof of factual correctness.'
    )
}

os.makedirs(os.path.dirname(out) or '.', exist_ok=True)

with open(out, 'w', encoding='utf8') as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

print('Saved:', out)
print('Alerts:', len(alerts))
print('LLM attempted:', result['llama_summary']['attempts'])
print('LLM accepted:', result['llama_summary']['accepted'])
print('Metrics: wall-time/RSS; TTFT/decode only when emitted by the ExecuTorch runner.')
PY
