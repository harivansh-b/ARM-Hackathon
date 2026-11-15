"""Per-category false-positive/negative report on the hand-written Indian hard set (synthetic)."""
import argparse, json, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "person-c"))
from guardian_models.runtime import SMSRuntime  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--artifact", required=True, type=Path)
    p.add_argument("--data", type=Path, nargs="+", default=[Path(__file__).with_name("hard_negatives.jsonl"), ROOT / "person-c/data/indian_hard_negatives.jsonl"])
    p.add_argument("--out", type=Path)
    a = p.parse_args()
    rt = SMSRuntime.from_artifact(a.artifact)
    rows = [json.loads(l) for f in a.data for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
    stats, wrong = defaultdict(lambda: [0, 0]), []
    for r in rows:
        out = rt.analyze(r["text"], sender=r.get("sender"))
        predicted = out["decision_state"] == "ALERT"  # REVIEW counted separately below
        review = out["decision_state"] == "REVIEW"
        bad = (predicted and r["label"] == 0) or (not predicted and not review and r["label"] == 1)
        key = (r["label"], r["category"], r["language"])
        stats[key][0] += 1
        stats[key][1] += int(bad)
        if bad or review:
            wrong.append((r["id"], r["label"], out["decision_state"], round(out["score"], 3), r["text"][:70]))
    fp = sum(v[1] for k, v in stats.items() if k[0] == 0); n0 = sum(v[0] for k, v in stats.items() if k[0] == 0)
    fn = sum(v[1] for k, v in stats.items() if k[0] == 1); n1 = sum(v[0] for k, v in stats.items() if k[0] == 1)
    print(f"legitimate: {fp}/{n0} wrongly ALERTed (FPR {fp/max(n0,1):.1%})   scams: {fn}/{n1} missed (FNR {fn/max(n1,1):.1%})")
    print("\nper category (label, category, language): errors/total")
    for k, v in sorted(stats.items()):
        print(f"  {k}: {v[1]}/{v[0]}")
    print("\nerrors and REVIEW cases:")
    for w in wrong:
        print("  ", w)
    if a.out:
        a.out.write_text(json.dumps({"fpr": fp / max(n0, 1), "fnr": fn / max(n1, 1), "n_legit": n0, "n_scam": n1}, indent=2))


if __name__ == "__main__":
    main()
