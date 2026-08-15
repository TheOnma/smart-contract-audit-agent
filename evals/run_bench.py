#!/usr/bin/env python3
"""
Retrieval benchmark: does rag/query.py surface the *right* prior finding
for a known bug pattern?

Ground truth = real, confirmed C4/Cantina findings already in the corpus
(rag/corpus-dreusd -> .rag/dreusd-db). Each query is phrased as an auditor
would describe a suspected bug pattern while reading code, NOT as the finding
title, so the eval measures genuine semantic retrieval.

Usage:
    python3 evals/run_bench.py --db .rag/dreusd-db --k 10
    python3 evals/run_bench.py --db .rag/dreusd-db --k 10 --full
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rag.query import load_openai_key, query_by_pattern  # noqa: E402
from evals.metrics import summarize_retrieval, format_table  # noqa: E402

BENCHMARK_FILE = Path(__file__).parent / "benchmark" / "cases.json"
RESULTS_DIR = Path(__file__).parent / "results"


def load_cases() -> dict:
    data = json.loads(BENCHMARK_FILE.read_text())
    return data


def run_case(case: dict, n_results: int, db_path: str, openai_key: str) -> dict:
    gt = set(case["ground_truth_ids"])
    t0 = time.time()
    results = query_by_pattern(case["query"], n_results=n_results,
                               db_path=db_path, openai_key=openai_key)
    latency = time.time() - t0

    first_rank = None
    hit_similarity = None
    for i, r in enumerate(results, start=1):
        if r["id"] in gt:
            first_rank = i
            hit_similarity = r.get("similarity")
            break

    return {
        "id": case["id"],
        "protocol": case["protocol"],
        "severity": case["severity"],
        "vuln_class": case["vuln_class"],
        "hit": first_rank is not None,
        "first_rank": first_rank,
        "hit_similarity": hit_similarity,
        "latency_s": round(latency, 2),
        "top_ids": [r["id"] for r in results[:5]],
        "query": case["query"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the retrieval benchmark.")
    parser.add_argument("--db", default=".rag/dreusd-db",
                        help="ChromaDB path (default: .rag/dreusd-db)")
    parser.add_argument("--k", type=int, default=10,
                        help="Top-k window for Recall@k (default: 10)")
    parser.add_argument("--n", type=int, default=None,
                        help="n_results passed to query_by_pattern (default: = k)")
    parser.add_argument("--full", action="store_true",
                        help="Print full per-case details including top-5 ids")
    parser.add_argument("--env", default=str(ROOT / ".env"),
                        help="Path to .env with OPENAI key")
    args = parser.parse_args()

    openai_key = load_openai_key(args.env)
    n_results = args.n or args.k
    data = load_cases()

    per_case = [run_case(c, n_results, args.db, openai_key)
                for c in data["cases"]]
    summary = summarize_retrieval(per_case, k=args.k)

    # Write machine-readable + human-readable results
    RESULTS_DIR.mkdir(exist_ok=True)
    (RESULTS_DIR / "latest.json").write_text(
        json.dumps({"summary": summary, "cases": per_case}, indent=2))
    (RESULTS_DIR / "report.md").write_text(
        format_table(summary, per_case))

    print(f"\nBenchmark: {summary['n_cases']} real confirmed findings | "
          f"Recall@{args.k} = {summary['recall_at_k']} | MRR = {summary['mrr']} | "
          f"mean hit sim = {summary['mean_hit_similarity']}\n")
    for c in per_case:
        rank = c["first_rank"] if c["first_rank"] is not None else "MISS"
        sim = f"{c['hit_similarity']:.3f}" if c.get("hit_similarity") is not None else "—"
        print(f"  {'✅' if c['hit'] else '❌'} {c['id']:<45} rank={rank:<5} sim={sim}")
        if args.full:
            print(f"      query: {c['query']}")
            print(f"      top5 : {c['top_ids']}")
    print(f"\nWrote {RESULTS_DIR / 'latest.json'} and {RESULTS_DIR / 'report.md'}\n")


if __name__ == "__main__":
    main()
