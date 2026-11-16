"""Run joinstr-difffuzz with vortex-ng registered as one more implementation.

Run from the root of a joinstr-difffuzz checkout (tools/joinstr-difffuzz/run.sh does):

    python3 drive.py <vortex adapter binary> <impls> replay <corpus dir>
    python3 drive.py <vortex adapter binary> <impls> campaign <cases> <seed>

`replay` is the harness's own replay loop with more detail: for every recorded case it says whether
the implementations still disagree and which of them vortex-ng sides with, and prints each group's
result where vortex-ng stands alone or crashes. `campaign` is the harness's fresh campaign, unchanged.
Nothing in the harness is patched: vortex-ng is added to its implementation table in memory.
"""
import json
import os
import sys

sys.path.insert(0, os.getcwd())

from driver import campaigns, run  # noqa: E402
from driver.client import Adapter  # noqa: E402
from driver.norm import classify  # noqa: E402

NAME = "vortex"


def replay(impls, corpus):
    adapters = {n: Adapter(n, run.IMPLS[n]) for n in impls}
    camps = {c.name: c for c in campaigns.ALL}
    counts = {"cases": 0, "skipped": 0, "errors": 0, "agree": 0, "diverge": 0, "alone": 0, "crash": 0}
    try:
        for fn in sorted(os.listdir(corpus)):
            doc = json.load(open(os.path.join(corpus, fn)))
            camp, p = camps[doc["campaign"]], doc["params"]
            if "producer" in p and p["producer"] not in impls:
                counts["skipped"] += 1
                continue
            counts["cases"] += 1
            try:
                observations = camp.run(p, adapters)
            except Exception as exc:  # one broken case must not end the replay
                counts["errors"] += 1
                print(f"{fn}: ERROR {type(exc).__name__}: {str(exc)[:160]}", flush=True)
                continue
            diverged = alone = crashed = False
            notes = []
            for op, results in observations:
                kind, _ = classify(results.get(NAME, {"unsupported": True}))
                by = run.groups(results)
                if kind == "crash":
                    crashed = True
                if len(by) > 1 or "crash" in by:
                    diverged = True
                    mine = next((g for g in by.values() if NAME in g), None)
                    if mine == [NAME] or kind == "crash":
                        alone = alone or mine == [NAME]
                        notes.append((op, by, results))
            status = "DIVERGES" if diverged else "agrees"
            flag = " VORTEX-ALONE" if alone else ""
            flag += " VORTEX-CRASH" if crashed else ""
            print(f"{fn}: {status}{flag}", flush=True)
            for op, by, results in notes:
                print(f"    op {op}: params {json.dumps(p, sort_keys=True)[:600]}")
                for key, group in by.items():
                    print(f"      {','.join(group)}: {key[:400]}")
                print(f"      vortex reply: {json.dumps(results.get(NAME))[:400]}")
            counts["agree" if not diverged else "diverge"] += 1
            counts["alone"] += alone
            counts["crash"] += crashed
    finally:
        for adapter in adapters.values():
            adapter.stop()
    print("SUMMARY " + " ".join(f"{k}={v}" for k, v in counts.items()), flush=True)


def main():
    binary, impls, mode = sys.argv[1], sys.argv[2].split(","), sys.argv[3]
    run.IMPLS[NAME] = [binary]
    if mode == "replay":
        replay(impls, sys.argv[4])
    elif mode == "campaign":
        sys.argv = ["driver.run", "--impls", ",".join(impls), "--cases", sys.argv[4], "--seed", sys.argv[5]]
        run.main()
    else:
        sys.exit("mode must be replay or campaign")


if __name__ == "__main__":
    main()
