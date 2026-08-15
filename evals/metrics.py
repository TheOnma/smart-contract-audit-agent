"""Retrieval metrics for the audit-findings benchmark.

Definitions (see EVALS_SPEC.md §2):
  Recall@k   = fraction of cases where at least one ground-truth finding
               chunk appears in the top-k retrieved results.
  MRR        = mean over cases of 1 / rank_of_first_correct_hit
               (0.0 if the correct finding is not retrieved at all).
  Mean hit similarity = average similarity of the highest-ranked correct hit
               (sanity check for the retrieval similarity threshold).
"""
from statistics import mean
from typing import Dict, List, Optional, Sequence


def reciprocal_rank(ranks: Sequence[Optional[int]]) -> float:
    """1 / rank of the first correct hit, or 0.0 if never hit."""
    for r in ranks:
        if r is not None:
            return 1.0 / r
    return 0.0


def recall_at_k(hits: Sequence[bool], k: int) -> float:
    """Fraction of cases with a correct hit within top-k."""
    if not hits:
        return 0.0
    return mean(1.0 if h else 0.0 for h in hits)


def mean_reciprocal_rank(rrs: Sequence[float]) -> float:
    if not rrs:
        return 0.0
    return mean(rrs)


def summarize_retrieval(
    cases: Sequence[Dict],  # list of {"hit": bool, "first_rank": int|None, "hit_similarity": float|None}
    k: int,
) -> Dict:
    """Aggregate per-case retrieval results into the summary metrics dict."""
    n = len(cases)
    hits_at_k = [c["hit"] for c in cases]
    rrs = [reciprocal_rank([c["first_rank"]]) for c in cases]
    sims = [c["hit_similarity"] for c in cases if c.get("hit_similarity") is not None]

    summary = {
        "n_cases": n,
        "k": k,
        "recall_at_k": round(recall_at_k(hits_at_k, k), 3),
        "mrr": round(mean_reciprocal_rank(rrs), 3),
        "mean_hit_similarity": round(mean(sims), 3) if sims else None,
        "misses": [c["id"] for c in cases if not c["hit"]],
    }
    return summary


# ── End-to-end (simulated review) metrics ─────────────────────────────────
#
# Definitions (EVALS_SPEC.md §2, detection eval):
#   Detection rate    = (# vulnerable reviews where the ground-truth finding is
#                       surfaced as a candidate) / (# vulnerable reviews).
#                       A candidate = retrieved finding with similarity >=
#                       threshold in Pass 1 (pattern) or Pass 2 (category) of
#                       the simulated reviewer. This is recall on bugs.
#   Top-candidate rate = fraction of detected reviews where the ground-truth
#                       finding is the #1 ranked surfaced candidate.
#   False-positive rate = (# clean reviews where >= 1 candidate surfaced) /
#                       (# clean reviews).
#   Mean candidates / review = how much noise the reviewer wades through.


def _candidates_at(results: Dict, t: float) -> Dict:
    return results["thresholds"].get(str(t), results["thresholds"].get(t, {}))


def summarize_e2e(
    positive: Sequence[Dict],
    clean: Sequence[Dict],
    thresholds: Sequence[float],
) -> Dict:
    """Aggregate per-review results into the detection-eval summary."""
    n = len(positive)
    ts = [str(t) for t in thresholds]

    summary = {
        "n_positive": n,
        "n_clean": len(clean),
        "thresholds": thresholds,
        "detection_rate": {},
        "top_candidate_rate": {},
        "mean_candidates_per_review": {},
        "false_positive_rate": {},
        "false_positive_rate_after_gate": {},
        "fp_gate_caught": {},
        "pass1_only": {},
        "pass2_only": {},
        "both_passes": {},
        "pass2_skipped": {},
        "fp_gate_overlap": {},
        "misses": {},
        "fp_clean_cases": {},
        "avg_latency_s": round(mean([c["latency_s"] for c in positive]), 2),
        "est_cost_per_review_usd": round(
            mean([c["est_cost_usd"] for c in positive]), 8),
    }

    for t in ts:
        det = [c["thresholds"][t]["detected"] for c in positive]
        top = [c["thresholds"][t]["gt_rank"] == 1
               for c in positive if c["thresholds"][t]["gt_rank"] is not None]
        cands = [len(c["thresholds"][t]["surfaced_ids"]) for c in positive]
        fp = [c["thresholds"][t]["false_positive"] for c in clean]
        # After the Pass 3 gate: a clean review only ships a false positive if
        # a candidate surfaced AND no triaged FP entry matched (the reviewer
        # double-checks against the FP corpus before reporting).
        fp_after = [
            c["thresholds"][t]["false_positive"] and not c["thresholds"][t]["fp_overlap"]
            for c in clean
        ]

        summary["detection_rate"][t] = round(mean(det), 3) if det else None
        summary["top_candidate_rate"][t] = round(mean(top), 3) if top else None
        summary["mean_candidates_per_review"][t] = round(mean(cands), 2)
        summary["false_positive_rate"][t] = round(mean(fp), 3) if fp else None
        summary["false_positive_rate_after_gate"][t] = round(mean(fp_after), 3) if fp_after else None
        summary["fp_gate_caught"][t] = sum(
            1 for c in clean
            if c["thresholds"][t]["false_positive"] and c["thresholds"][t]["fp_overlap"])
        summary["pass1_only"][t] = sum(
            1 for c in positive if c["thresholds"][t]["detected"]
            and c["thresholds"][t]["pass1"] and not c["thresholds"][t]["pass2"])
        summary["pass2_only"][t] = sum(
            1 for c in positive if c["thresholds"][t]["detected"]
            and not c["thresholds"][t]["pass1"] and c["thresholds"][t]["pass2"])
        summary["both_passes"][t] = sum(
            1 for c in positive if c["thresholds"][t]["detected"]
            and c["thresholds"][t]["pass1"] and c["thresholds"][t]["pass2"])
        summary["pass2_skipped"][t] = sum(
            1 for c in positive if c["thresholds"][t]["pass2_skipped"])
        summary["fp_gate_overlap"][t] = sum(
            1 for c in positive if c["thresholds"][t]["fp_overlap"])
        summary["misses"][t] = [
            c["id"] for c in positive if not c["thresholds"][t]["detected"]]
        summary["fp_clean_cases"][t] = [
            c["id"] for c in clean if c["thresholds"][t]["false_positive"]]

    return summary


def format_e2e_table(summary: Dict, positive: Sequence[Dict], clean: Sequence[Dict]) -> str:
    """Render the detection-eval summary + per-case tables as markdown."""
    ts = [str(t) for t in summary["thresholds"]]
    # Headline = the reviewer's 0.5 rule (rag-reviewer.md: 'similarity < 0.5 ->
    # don't report'); fall back to the highest threshold.
    h = "0.5" if 0.5 in summary["thresholds"] else str(summary["thresholds"][-1])

    def _fmt(v):
        return "—" if v is None else f"{v}"

    lines = [
        "# End-to-End Detection Benchmark (simulated review)",
        "",
        f"**{summary['n_positive']} vulnerable code surfaces** (real confirmed C4/Cantina findings, "
        f"input = the code an auditor sees, no vulnerability language) + "
        f"**{summary['n_clean']} clean surfaces**. Reviewer = deterministic "
        "implementation of `agents/rag-reviewer.md` (Pass 1 pattern match, Pass 2 "
        "category sweep, Pass 3 FP check). Candidate = finding with similarity ≥ threshold.",
        "",
        "| Metric | " + " | ".join(f"t={t}" for t in ts) + " |",
        "|---|" + "---|" * len(ts),
        f"| Detection rate (recall on bugs) | " + " | ".join(
            f"{summary['detection_rate'][t]}" for t in ts) + " |",
        f"| Top-candidate rate (GT ranked #1) | " + " | ".join(
            _fmt(summary['top_candidate_rate'][t]) for t in ts) + " |",
        f"| Mean candidates per review | " + " | ".join(
            f"{summary['mean_candidates_per_review'][t]}" for t in ts) + " |",
        f"| False-positive rate (clean) | " + " | ".join(
            _fmt(summary['false_positive_rate'][t]) for t in ts) + " |",
        f"| False-positive rate after FP gate | " + " | ".join(
            _fmt(summary['false_positive_rate_after_gate'][t]) for t in ts) + " |",
        "",
        f"At the headline threshold **t={h}** (the reviewer prompt's 'similarity < 0.5 → don't report' "
        f"rule): detected {summary['detection_rate'][h]} ({summary['n_positive'] - len(summary['misses'][h])}/"
        f"{summary['n_positive']}), of which pass-1-only {summary['pass1_only'][h]}, "
        f"pass-2-only {summary['pass2_only'][h]}, both {summary['both_passes'][h]}; "
        f"{summary['pass2_skipped'][h]} reviews had no category signal in the code (Pass 2 skipped); "
        f"{summary['fp_gate_overlap'][h]} had a similar false-positive entry (reviewer double-checks).",
        "",
        "## Per-case (vulnerable)",
        "",
        "| Case | Severity | Detected | GT rank | Pass | FP entry | Latency (s) |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in positive:
        r = c["thresholds"][h]
        rank = r["gt_rank"] if r["gt_rank"] is not None else "—"
        passes = []
        if r["pass1"]:
            passes.append("P1")
        if r["pass2"]:
            passes.append("P2")
        if not passes:
            passes.append("—")
        fp = "⚠️" if r["fp_overlap"] else "—"
        lines.append(
            f"| {c['id']} | {c['severity']} | {'✅' if r['detected'] else '❌'} "
            f"| {rank} | {'+'.join(passes)} | {fp} | {c['latency_s']} |")

    lines += ["", "## Clean surfaces (false-positive check)", "",
              "| Case | Candidate surfaced (t=" + h + ") | FP gate |", "|---|---|---|"]
    for c in clean:
        r = c["thresholds"][h]
        n_c = len(r["surfaced_ids"])
        surf = f"⚠️ FP ({n_c} candidates)" if r["false_positive"] else "✅ none"
        if r["fp_overlap"] and r["false_positive"]:
            gate = "✅ caught"
        elif r["fp_overlap"]:
            gate = "⚠️ flagged (no candidate)"
        else:
            gate = "—"
        lines.append(f"| {c['id']} | {surf} | {gate} |")

    lines += ["", f"FP gate: Pass 3 matches the clean surface against triaged "
              "false-positives corpus entries; a clean review counts as a "
              f"*shipped* false positive only if a candidate surfaced and the gate "
              f"did NOT fire (gate caught {summary['fp_gate_caught'][h]}/"
              f"{len(summary['fp_clean_cases'][h])} of the pre-gate FPs at t={h}).", ""]

    for t in ts:
        if summary["misses"][t]:
            lines += ["", f"### Misses at t={t}", ""]
            lines += [f"- {mid}" for mid in summary["misses"][t]]

    lines += ["", "Cost: text-embedding-3-small (~$0.02/1M tokens), 3 embedding queries per review "
              f"(Pass 1 + Pass 2 + Pass 3). Est. mean cost {summary['est_cost_per_review_usd']} USD/review. "
              f"Mean latency {summary['avg_latency_s']}s/review.", ""]
    return "\n".join(lines)


def format_table(summary: Dict, per_case: Sequence[Dict]) -> str:
    """Render the summary + per-case table as markdown for evals/results/report.md."""
    lines = [
        "# Retrieval Benchmark Results",
        "",
        f"**{summary['n_cases']} real confirmed C4/Cantina findings**, "
        f"Recall@{summary['k']} = **{summary['recall_at_k']}**, "
        f"MRR = **{summary['mrr']}**",
        "",
        "| Metric | Score |",
        "|---|---|",
        f"| Recall@{summary['k']} | {summary['recall_at_k']} |",
        f"| MRR | {summary['mrr']} |",
        f"| Mean hit similarity | {summary['mean_hit_similarity'] or '—'} |",
        "",
        "## Per-case",
        "",
        "| Case | Severity | Found | First rank | Hit similarity |",
        "|---|---|---|---|---|",
    ]
    for c in per_case:
        rank = c["first_rank"] if c["first_rank"] is not None else "—"
        sim = f"{c['hit_similarity']:.3f}" if c.get("hit_similarity") is not None else "—"
        lines.append(
            f"| {c['id']} | {c['severity']} | {'✅' if c['hit'] else '❌'} | {rank} | {sim} |"
        )
    if summary.get("misses"):
        lines += ["", "### Misses", ""]
        lines += [f"- {mid}" for mid in summary["misses"]]
    lines.append("")
    return "\n".join(lines)
