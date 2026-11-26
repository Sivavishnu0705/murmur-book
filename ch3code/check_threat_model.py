# Listing 3.2 — Validate the threat model and print a ranked checklist.
# Usage: python3 check_threat_model.py murmur-threat-model.yaml
import sys
import yaml   # pip install pyyaml

STRIDE = set("STRIDE")
STATUSES = {"open", "mitigated", "accepted"}

def load(path):
    with open(path) as f:
        return yaml.safe_load(f)

def check(tm):
    errors = []
    ids = {k: {x["id"] for x in tm.get(k, [])}
           for k in ("assets", "adversaries", "trust_boundaries", "goals")}
    for g in tm.get("goals", []):
        for field in ("asset", "adversary", "property", "assumptions", "out_of_scope"):
            if field not in g:
                errors.append(f"{g['id']}: missing '{field}'")
        if g.get("asset") not in ids["assets"]:
            errors.append(f"{g['id']}: unknown asset {g.get('asset')}")
        if g.get("adversary") not in ids["adversaries"]:
            errors.append(f"{g['id']}: unknown adversary {g.get('adversary')}")
    for t in tm.get("threats", []):
        tid = t["id"]
        if t.get("stride") not in STRIDE:
            errors.append(f"{tid}: stride must be one of S,T,R,I,D,E")
        if t.get("status") not in STATUSES:
            errors.append(f"{tid}: bad status {t.get('status')}")
        for key, kind in (("asset", "assets"), ("adversary", "adversaries"),
                          ("boundary", "trust_boundaries")):
            if t.get(key) not in ids[kind]:
                errors.append(f"{tid}: unknown {key} {t.get(key)}")
        for g in t.get("violates", []):
            if g not in ids["goals"]:
                errors.append(f"{tid}: violates unknown goal {g}")
        for k in ("likelihood", "impact"):
            if not 1 <= int(t.get(k, 0)) <= 5:
                errors.append(f"{tid}: {k} must be 1..5")
        if t.get("status") == "accepted" and not t.get("rationale"):
            errors.append(f"{tid}: accepted risks need a written rationale")
    return errors

def ranked(tm):
    return sorted(tm.get("threats", []),
                  key=lambda t: (-(t["likelihood"] * t["impact"]), t["id"]))

if __name__ == "__main__":
    tm = load(sys.argv[1])
    errs = check(tm)
    for e in errs:
        print("ERROR:", e)
    if errs:
        sys.exit(1)
    print(f"{'risk':>4}  {'id':<5} {'status':<10} title")
    for t in ranked(tm):
        print(f"{t['likelihood'] * t['impact']:>4}  {t['id']:<5} {t['status']:<10} {t['title']}")
