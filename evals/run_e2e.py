#!/usr/bin/env python3
"""
End-to-end detection eval: does the RAG + reviewer workflow actually surface a
candidate finding during a simulated review?

The real reviewer (agents/rag-reviewer.md) runs inside Claude Code — this harness
implements its decision logic deterministically so it's reproducible and cheap:

  Pass 1 — Pattern match : query_by_pattern(code_surface, n=5)
  Pass 2 — Category sweep : query_by_category(protocol_type, class, n=5), where
            class is derived FROM THE CODE SURFACE ITSELF via ingest.detect_category
            (same keyword logic the reviewer's "identify the vulnerability
            categories most relevant to this function" step approximates).
            Skipped when the surface carries no category signal.
  Pass 3 — FP check       : query_false_positives(code_surface, n=3) — overlaps
            with the corpus's false-positives.md entries are reported (the
            reviewer double-checks) but not a hard kill.

Input = the code surface an auditor sees (function signatures, identifiers,
logic fragments — NO vulnerability language; the vulnerability is what's missing).
A finding is a *candidate* if similarity >= threshold in Pass 1 or Pass 2
(the prompt rule: "Findings with similarity < 0.5 ... don't report").

Metrics (EVALS_SPEC.md §2): detection rate, top-candidate rate, mean candidates
per review, false-positive rate (clean surfaces), per-pass contribution,
cost & latency.

Usage:
    python3 evals/run_e2e.py --db .rag/dreusd-db
    python3 evals/run_e2e.py --db .rag/dreusd-db --thresholds 0.4,0.5,0.6 --full
"""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rag.query import (  # noqa: E402
    load_openai_key, query_by_pattern, query_by_category, query_false_positives,
)
from rag.ingest import detect_category  # noqa: E402
from evals.metrics import summarize_e2e, format_e2e_table  # noqa: E402

BENCH_DIR = Path(__file__).parent / "benchmark"
RESULTS_DIR = Path(__file__).parent / "results"

EMBEDDING_COST_PER_1M = 0.02  # text-embedding-3-small, USD


def est_tokens(text: str) -> float:
    return len(text) / 4.0  # ~4 chars per token


class SimulatedReviewer:
    """Deterministic implementation of agents/rag-reviewer.md."""

    def __init__(self, db_path: str, openai_key: str, n: int = 5):
        self.db_path = db_path
        self.openai_key = openai_key
        self.n = n
        self.latency_s = 0.0
        self.tokens = 0.0

    def _query(self, fn, *args) -> list:
        t0 = time.time()
        try:
            results = fn(*args)
        finally:
            self.latency_s += time.time() - t0
        return results

    def review(self, surface: str, protocol_type: str) -> dict:
        """Run the three passes over one code surface. Returns per-pass results."""
        self.latency_s = 0.0
        self.tokens = 0.0

        # ── Pass 1: pattern match on the code surface ─────────────────────
        self.tokens += est_tokens(surface)
        pass1 = self._query(query_by_pattern, surface, self.n,
                            None, self.db_path, self.openai_key)

        # ── Pass 2: category sweep, class derived from the code itself ────
        cls = detect_category(surface)
        pass2 = []
        pass2_skipped = cls == "logic"
        if not pass2_skipped:
            q = f"{protocol_type} {cls} vulnerability exploit"
            self.tokens += est_tokens(q)
            pass2 = self._query(query_by_category, protocol_type, cls, self.n,
                                None, self.db_path, self.openai_key)

        # ── Pass 3: false-positive check ──────────────────────────────────
        self.tokens += est_tokens(f"false positive not exploitable safe by design {surface}")
        pass3 = self._query(query_false_positives, surface, 3,
                            self.db_path, self.openai_key)

        return {
            "pass1": pass1,
            "pass2": pass2,
            "pass3": pass3,
            "pass2_skipped": pass2_skipped,
            "category_signal": cls,
        }


def evaluate_case(reviewer: SimulatedReviewer, case: dict, surface: str,
                  thresholds: list) -> dict:
    rev = reviewer.review(surface, case.get("protocol_type", "lending"))
    gt = set(case["ground_truth_ids"])
    cost = reviewer.tokens / 1e6 * EMBEDDING_COST_PER_1M

    # Merge candidates from Pass 1 + Pass 2 (dedup by id, keep best similarity)
    merged = {}
    for r in rev["pass1"] + rev["pass2"]:
        if r["id"] not in merged or (r.get("similarity") or 0) > (merged[r["id"]].get("similarity") or 0):
            merged[r["id"]] = r
    ranked = sorted(merged.values(), key=lambda r: r.get("similarity") or 0, reverse=True)

    th = {}
    for t in thresholds:
        surfaced = [r for r in ranked if (r.get("similarity") or 0) >= t]
        gt_rank = next((i + 1 for i, r in enumerate(surfaced) if r["id"] in gt), None)
        gt_hit = next((r for r in surfaced if r["id"] in gt), None)
        pass1_hit = any(r["id"] in gt for r in rev["pass1"] if (r.get("similarity") or 0) >= t)
        pass2_hit = any(r["id"] in gt for r in rev["pass2"] if (r.get("similarity") or 0) >= t)
        fp_overlap = any((r.get("similarity") or 0) >= t for r in rev["pass3"])
        th[str(t)] = {
            "surfaced_ids": [r["id"] for r in surfaced],
            "gt_rank": gt_rank,
            "detected": gt_rank is not None,
            "pass1": pass1_hit,
            "pass2": pass2_hit,
            "pass2_skipped": rev["pass2_skipped"],
            "category_signal": rev["category_signal"],
            "fp_overlap": fp_overlap,
            "gt_hit_similarity": round(gt_hit["similarity"], 3) if gt_hit else None,
        }

    return {
        "id": case["id"],
        "protocol": case.get("protocol", "?"),
        "severity": case.get("severity", "?"),
        "vuln_class": case.get("vuln_class", "?"),
        "latency_s": round(reviewer.latency_s, 2),
        "est_cost_usd": round(cost, 8),
        "thresholds": th,
    }


def evaluate_clean(reviewer: SimulatedReviewer, clean: dict, thresholds: list) -> dict:
    surface = "\n".join(clean["code_surface"])
    rev = reviewer.review(surface, clean.get("protocol_type", "lending"))
    cost = reviewer.tokens / 1e6 * EMBEDDING_COST_PER_1M

    merged = {}
    for r in rev["pass1"] + rev["pass2"]:
        if r["id"] not in merged or (r.get("similarity") or 0) > (merged[r["id"]].get("similarity") or 0):
            merged[r["id"]] = r
    ranked = sorted(merged.values(), key=lambda r: r.get("similarity") or 0, reverse=True)

    th = {}
    for t in thresholds:
        surfaced = [r for r in ranked if (r.get("similarity") or 0) >= t]
        th[str(t)] = {
            "surfaced_ids": [r["id"] for r in surfaced],
            "false_positive": len(surfaced) > 0,
            # Pass 3 gate: a triaged FP entry similar to this clean surface.
            # If it fires, the reviewer double-checks and (in the modeled
            # workflow) does not ship the finding.
            "fp_overlap": any((r.get("similarity") or 0) >= t for r in rev["pass3"]),
        }

    return {
        "id": clean["id"],
        "latency_s": round(reviewer.latency_s, 2),
        "est_cost_usd": round(cost, 8),
        "thresholds": th,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the end-to-end detection benchmark.")
    parser.add_argument("--db", default=".rag/dreusd-db", help="ChromaDB path")
    parser.add_argument("--env", default=str(ROOT / ".env"), help="Path to .env with OPENAI key")
    parser.add_argument("--n", type=int, default=5, help="n_results per pass (default 5)")
    parser.add_argument("--thresholds", default="0.4,0.5,0.6",
                        help="Similarity thresholds to report (default 0.4,0.5,0.6)")
    parser.add_argument("--full", action="store_true",
                        help="Print per-case candidate details")
    args = parser.parse_args()

    thresholds = [float(x) for x in args.thresholds.split(",")]
    openai_key = load_openai_key(args.env)
    reviewer = SimulatedReviewer(args.db, openai_key, n=args.n)

    cases = json.loads((BENCH_DIR / "cases.json").read_text())["cases"]
    surfaces = json.loads((BENCH_DIR / "code_surfaces.json").read_text())["surfaces"]
    clean = json.loads((BENCH_DIR / "clean_cases.json").read_text())["clean_cases"]

    surf_by_id = {s["id"]: s for s in surfaces}
    case_by_id = {c["id"]: c for c in cases}

    missing = set(case_by_id) ^ set(surf_by_id)
    if missing:
        print(f"ERROR: id mismatch between cases.json and code_surfaces.json: {missing}")
        sys.exit(1)

    positive, clean_results = [], []
    for cid, case in case_by_id.items():
        surface = "\n".join(surf_by_id[cid]["code_surface"])
        result = evaluate_case(reviewer, case, surface, thresholds)
        positive.append(result)

    for c in clean:
        surface = "\n".join(c["code_surface"])
        clean_results.append(evaluate_clean(reviewer, c, thresholds))

    summary = summarize_e2e(positive, clean_results, thresholds)

    RESULTS_DIR.mkdir(exist_ok=True)
    (RESULTS_DIR / "e2e_latest.json").write_text(json.dumps({
        "summary": summary, "positive": positive, "clean": clean_results}, indent=2))
    (RESULTS_DIR / "e2e_report.md").write_text(
        format_e2e_table(summary, positive, clean_results))

    # Headline = the reviewer's 0.5 rule (rag-reviewer.md: 'Findings with
    # similarity < 0.5 ... don't report'); fall back to the last threshold.
    h = "0.5" if 0.5 in thresholds else str(thresholds[-1])
    print(f"\nEnd-to-end detection benchmark | {summary['n_positive']} vulnerable + "
          f"{summary['n_clean']} clean surfaces")
    print(f"  detection rate (t={thresholds[0]}): {summary['detection_rate'][str(thresholds[0])]}")
    print(f"  detection rate (t={h}): {summary['detection_rate'][h]}   "
          f"← headline (reviewer's 0.5 rule)")
    print(f"  top-candidate rate (t={h}): {summary['top_candidate_rate'][h]}")
    print(f"  mean candidates/review (t={h}): {summary['mean_candidates_per_review'][h]}")
    n_pre = len(summary['fp_clean_cases'][h])
    print(f"  false-positive rate (t={h}): {summary['false_positive_rate'][h]}   "
          f"clean: {summary['fp_clean_cases'][h] or 'none'}")
    print(f"  false-positive rate AFTER FP gate (t={h}): "
          f"{summary['false_positive_rate_after_gate'][h]}   "
          f"(gate caught {summary['fp_gate_caught'][h]}/{n_pre} of the pre-gate FPs)")
    print(f"  pass1-only/pass2-only/both (t={h}): "
          f"{summary['pass1_only'][h]}/{summary['pass2_only'][h]}/{summary['both_passes'][h]}")
    print(f"  avg latency: {summary['avg_latency_s']}s/review | "
          f"est. cost: ${summary['est_cost_per_review_usd']}/review\n")

    for c in positive:
        r = c["thresholds"][h]
        rank = r["gt_rank"] if r["gt_rank"] is not None else "MISS"
        passes = "+".join(p for p, hit in (("P1", r["pass1"]), ("P2", r["pass2"])) if hit) or "—"
        fp = " ⚠️FP-entry" if r["fp_overlap"] else ""
        sim = f"{r['gt_hit_similarity']}" if r["gt_hit_similarity"] is not None else "—"
        print(f"  {'✅' if r['detected'] else '❌'} {c['id']:<42} rank={rank:<5} "
              f"sim={sim:<5} passes={passes}{fp}")
        if args.full:
            print(f"      top candidates: {r['surfaced_ids'][:6]}")
            print(f"      query pass2 signal: {r.get('category_signal', '—')} "
                  f"(skipped: {r['pass2_skipped']})")
    for c in clean_results:
        r = c["thresholds"][h]
        if r["false_positive"]:
            mark = (f"FP! gate-caught  {r['surfaced_ids'][:2]}"
                    if r["fp_overlap"] else f"FP! SHIPPED  {r['surfaced_ids'][:2]}")
        else:
            mark = "clean"
        print(f"  · {c['id']:<42} {mark}")
    print(f"\nWrote {RESULTS_DIR / 'e2e_latest.json'} and {RESULTS_DIR / 'e2e_report.md'}\n")


if __name__ == "__main__":
    main()
