# Eval Harness Spec — Smart Contract Audit Agent

**Goal:** turn this repo from "an AI audit tool I built" into "an AI audit tool with a **published eval harness and observability**" — the single strongest signal a 2026 AI-engineering hiring manager looks for. When you're done, your README shows a results table with real numbers, and you can answer "how do you know it works?" in specifics, not adjectives.

Two eval layers, because this is an agentic system:

1. **Retrieval eval (component)** — does `rag/query.py` surface the *right* prior finding for a known bug? Metrics: Recall@k, MRR.
2. **Detection eval (end-to-end / trajectory)** — given a contract with a *known* vulnerability, does the full pipeline (RAG → blackhat → synthesis) flag the correct vulnerability class and severity? Metrics: detection rate, false-positive rate, severity accuracy, plus cost & latency.

Ship both. Retrieval alone is table stakes; the end-to-end trajectory eval is what proves you've actually run an agent in anger.

---

## 1. Build the benchmark dataset

You need **labeled, known-vulnerable contracts** — input contract + ground-truth vulnerability. You already own most of the sources.

### Where the labeled data comes from (no scraping needed)
- **Your own findings** — the Revert Finance medium, the `stableswap-hooks` findings (`finding-convergence-dead-zone.md`, `finding-amp-zero-brick.md`), the dreapp/dreusd findings, midnight `attack-plan-finding-H-M.md`. These are gold: real bugs, real writeups, and you understand them cold.
- **Cyfrin `sc-exploits-minimized`** (already in `Documents/learn_solidity_security/security-lessons/sc-exploits-minimized`) — minimal, cleanly-labeled vuln examples (reentrancy, weak randomness, etc.). Perfect starter set.
- **Public labeled sets** — Trail of Bits "Not So Smart Contracts", SmartBugs-curated, DeFiHackLabs (each hack has a known root cause). Pick ~15–20 across categories.

### Directory layout
```
evals/
├── benchmark/
│   ├── 001-reentrancy-callback/
│   │   ├── contract.sol            # the vulnerable contract (input)
│   │   └── label.json              # ground truth (below)
│   ├── 002-rounding-muldivdown/
│   │   ├── contract.sol
│   │   └── label.json
│   └── ...                          # aim for 20–30 cases at first
├── run_bench.py                     # the harness (skeleton below)
├── metrics.py                       # metric functions
└── results/
    ├── latest.json                  # machine-readable run output
    └── report.md                    # human-readable table (regenerated each run)
```

### `label.json` schema
```json
{
  "id": "002-rounding-muldivdown",
  "protocol_type": "lending",
  "vuln_class": "rounding-direction",
  "severity": "medium",
  "expected_finding_keywords": ["mulDivDown", "rounding toward zero", "shares"],
  "canonical_finding_id": "morpho-blue/spearbit-2024#3",
  "notes": "Deposit rounds shares down, attacker inflates share price via donation."
}
```
- `vuln_class` — controlled vocabulary you define (reentrancy, rounding-direction, oracle-staleness, access-control, callback-ordering, domain-separator-proxy, etc.). Keep a `evals/vuln_classes.md` list.
- `canonical_finding_id` — the corpus document + finding your RAG *should* retrieve. Enables the retrieval metric.
- Include **3–5 clean (non-vulnerable) contracts** too, so you can measure false positives. Label them `vuln_class: "none"`.

---

## 2. Metric definitions (put the formulas in `evals/metrics.py`)

### Retrieval metrics (from `rag/query.py` output)
For each benchmark case, run `query.py --pattern "<derived query>"`, take top-k results, check whether `canonical_finding_id` (or a keyword match against `expected_finding_keywords`) appears.

- **Recall@k** = (# cases where the correct finding is in top-k) / (total cases). Report **Recall@5** and **Recall@10**.
- **MRR** (Mean Reciprocal Rank) = mean of (1 / rank of first correct hit). Rewards putting the right finding near the top.
- **Mean hit similarity** = average similarity score of the correct hit (sanity check on your threshold).

### Detection metrics (end-to-end pipeline)
Run the full flow per case; capture the pipeline's final verdict (vuln_class + severity).

- **Detection rate (recall on bugs)** = (# vulnerable cases where predicted `vuln_class` matches ground truth) / (# vulnerable cases). **This is your headline number.**
- **False-positive rate** = (# clean cases flagged as vulnerable) / (# clean cases). Low FP rate is what separates a useful tool from a noise machine — call it out.
- **Severity accuracy** = (# cases where predicted severity == true severity) / (# detected cases).
- **Precision** (if you allow multiple predictions) = correct flags / total flags.

### Efficiency metrics (the "scarce skill" — cost optimization)
Log per case and report the mean:
- **Cost per contract** ($) — sum of embedding + LLM tokens × price.
- **Tokens per contract** (prompt + completion).
- **Latency** (wall-clock seconds per case).
Then show one optimization: e.g. "switched HyDE/synthesis to a cheaper model for pass-1, cut cost 42% with detection rate flat (0.71 → 0.70)." That single sentence is a hiring signal on its own.

---

## 3. Harness skeleton — `evals/run_bench.py`

```python
"""
Runs the benchmark over evals/benchmark/*, computes metrics, writes results/.
Usage: python3 evals/run_bench.py --k 10 --trace
"""
import json, time, glob, argparse, pathlib
from statistics import mean

# import your existing code — adjust names to match rag/query.py
from rag.query import retrieve            # -> returns [(finding_id, score, text), ...]
# from agents.pipeline import audit_contract  # your end-to-end entry point

def load_cases():
    for d in sorted(glob.glob("evals/benchmark/*/")):
        label = json.load(open(pathlib.Path(d) / "label.json"))
        contract = (pathlib.Path(d) / "contract.sol").read_text()
        yield label, contract

def eval_retrieval(label, k):
    q = " ".join(label["expected_finding_keywords"])
    hits = retrieve(q, k=k)                       # top-k finding ids + scores
    ids = [h[0] for h in hits]
    correct = label.get("canonical_finding_id")
    rank = next((i + 1 for i, fid in enumerate(ids) if correct and correct in fid), None)
    return {
        "hit@k": rank is not None,
        "rr": (1.0 / rank) if rank else 0.0,
        "top_score": hits[0][1] if hits else 0.0,
    }

def eval_detection(label, contract):
    t0 = time.time()
    # result = audit_contract(contract)   # -> {"vuln_class":..., "severity":..., "tokens":..., "cost":...}
    result = {"vuln_class": "TODO", "severity": "TODO", "tokens": 0, "cost": 0.0}
    dt = time.time() - t0
    is_bug = label["vuln_class"] != "none"
    predicted_bug = result["vuln_class"] != "none"
    return {
        "is_bug": is_bug,
        "detected": is_bug and result["vuln_class"] == label["vuln_class"],
        "false_positive": (not is_bug) and predicted_bug,
        "severity_ok": result["severity"] == label["severity"],
        "cost": result["cost"], "tokens": result["tokens"], "latency": dt,
    }

def main(k, trace):
    R, D = [], []
    for label, contract in load_cases():
        R.append(eval_retrieval(label, k))
        D.append(eval_detection(label, contract))
        # if trace: log_trajectory(label, ...)  # see section 4

    bugs = [d for d in D if d["is_bug"]]
    clean = [d for d in D if not d["is_bug"]]
    summary = {
        "n_cases": len(D),
        "recall_at_k": round(mean(r["hit@k"] for r in R), 3),
        "mrr": round(mean(r["rr"] for r in R), 3),
        "detection_rate": round(mean(d["detected"] for d in bugs), 3) if bugs else None,
        "false_positive_rate": round(mean(d["false_positive"] for d in clean), 3) if clean else None,
        "severity_accuracy": round(mean(d["severity_ok"] for d in bugs if d["detected"]), 3) if bugs else None,
        "avg_cost_usd": round(mean(d["cost"] for d in D), 4),
        "avg_latency_s": round(mean(d["latency"] for d in D), 2),
        "k": k,
    }
    json.dump({"summary": summary, "retrieval": R, "detection": D},
              open("evals/results/latest.json", "w"), indent=2)
    write_report_md(summary)   # regenerates evals/results/report.md
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--k", type=int, default=10)
    p.add_argument("--trace", action="store_true")
    a = p.parse_args()
    main(a.k, a.trace)
```

The `retrieve()` / `audit_contract()` names are placeholders — wire them to whatever `rag/query.py` and your agent entry point actually expose. If there's no single-function end-to-end entry yet, add one (`agents/pipeline.py: audit_contract(source) -> verdict`); that refactor is itself good portfolio hygiene.

---

## 4. Observability / trajectory logging (the agentic differentiator)

Interviewers explicitly ask "what do you use to trace a failing agent trajectory?" You want a fast, opinionated answer.

**Recommended: Arize Phoenix** — open-source, free, self-hostable, OpenTelemetry-based, strong for LLM traces. (Braintrust or LangSmith free tiers are fine alternatives; pick one and have an opinion about why.)

Log, per case, the **full trajectory** as one trace with spans:
1. `retrieve` — query, top-k finding ids + scores
2. `blackhat` — the attacker-reasoning prompt + output (from `agents/blackhat.md`)
3. `fuzz` — whether Foundry/Echidna found a counterexample
4. `synthesis` — final verdict (`agents/synthesis.md`)

Minimum-viable version if you don't want a dependency: write each trajectory to `evals/results/traces/<case_id>.jsonl`, one line per span, and add a 30-line HTML viewer. Even that lets you say "I log and inspect agent trajectories and evaluate intermediate steps, not just final output" — which is the point.

**Trajectory (step-level) evals** — beyond the final verdict, score intermediate steps: did `retrieve` surface the right pattern (you already measure this)? did `blackhat` name the real attack path? Report a per-stage success rate so you can point to *where* the agent fails. That's the sentence that ends the interview in your favor.

---

## 5. How to present it (recruiter-facing)

Add an **`## Evaluation`** section to the README with a table like this (fill with your real numbers):

```
## Evaluation

Benchmarked on 27 labeled cases (22 vulnerable across 8 classes + 5 clean contracts),
drawn from public exploit datasets and my own competitive-audit findings.

| Metric                     | Score  |
|----------------------------|--------|
| Retrieval Recall@5         | 0.82   |
| Retrieval Recall@10        | 0.91   |
| MRR                        | 0.68   |
| End-to-end detection rate  | 0.71   |
| False-positive rate        | 0.10   |
| Severity accuracy          | 0.79   |
| Avg cost / contract        | $0.03  |
| Avg latency / contract     | 8.4 s  |

Cost note: routing pass-1 pattern-matching to a smaller model cut cost 42%
(0.71 → 0.70 detection rate — flat). Full methodology + per-case results in `evals/`.

Reproduce: `python3 evals/run_bench.py --k 10 --trace`
```

Also: commit `evals/results/report.md` so the numbers are visible on GitHub without running anything, and drop one screenshot of a Phoenix/trace view into the README.

---

## 6. Build order (1 focused day)

1. Create `evals/benchmark/` with **8 cases** first (5 from `sc-exploits-minimized` + 3 of your own findings). Don't wait for 30.
2. Write `evals/metrics.py` + `evals/run_bench.py`; wire the retrieval path (you have `query.py` already) → get Recall@k + MRR working end to end.
3. Add the end-to-end `audit_contract()` entry point; get detection rate on your 8 cases.
4. Add trajectory logging (JSONL first, Phoenix if time allows).
5. Expand to ~20–30 cases, regenerate `report.md`, paste the table into the README, screenshot a trace.

Ship step 2's numbers even if small — "Recall@10 = 0.9 on a 12-case benchmark, methodology public" beats "no evals" by a mile, and beats a shiny new project by more.
