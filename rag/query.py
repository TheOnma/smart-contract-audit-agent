"""
Query the audit findings RAG.
Two-pass strategy: (1) structural pattern, (2) protocol type × vulnerability category.
Always run Pass 3 (false positive check) before writing a PoC.

Usage:
    python3 rag/query.py --pattern "callback before state write with ERC20 transfer"
    python3 rag/query.py --category "fixed-rate-lending arithmetic"
    python3 rag/query.py --fp "reentrancy during liquidation callback"
    python3 rag/query.py --severity high --n 10
"""
import chromadb
import argparse
import sys
from typing import List, Dict, Optional

DEFAULT_DB = ".rag/db"


# ── Collection helper ───────────────────────────────────────────────────────

def _get_collection(db_path: str):
    try:
        client = chromadb.PersistentClient(path=db_path)
        return client.get_collection("audit_findings")
    except Exception:
        print(f"ERROR: No RAG database found at {db_path}")
        print("Run: python3 rag/ingest.py --corpus rag/corpus --db .rag/db")
        sys.exit(1)


def _format_results(results) -> List[Dict]:
    out = []
    if not results["ids"] or not results["ids"][0]:
        return out
    for i, doc_id in enumerate(results["ids"][0]):
        meta     = results["metadatas"][0][i]
        distance = results["distances"][0][i] if results.get("distances") else None
        text     = results["documents"][0][i]
        out.append({
            "id":           doc_id,
            "protocol":     meta.get("protocol_name", "?"),
            "protocol_type":meta.get("protocol_type", "?"),
            "severity":     meta.get("severity", "?"),
            "category":     meta.get("category", "?"),
            "is_fp":        meta.get("is_false_positive", "False") == "True",
            "has_code":     meta.get("has_code", "False") == "True",
            "similarity":   round(1 - distance, 3) if distance is not None else None,
            "text":         text,
            "source":       meta.get("source_file", ""),
        })
    return out


# ── Query functions ──────────────────────────────────────────────────────────

def query_by_pattern(
    code_or_description: str,
    n_results: int = 5,
    severity_filter: Optional[str] = None,
    exclude_fp: bool = False,
    db_path: str = DEFAULT_DB,
) -> List[Dict]:
    """
    Pass 1 — Structural pattern query.
    Use when reviewing a specific function or code snippet.
    Example: "mulDivDown unchecked block lossFactor near max"
    """
    collection = _get_collection(db_path)
    where_clauses = []
    if severity_filter:
        where_clauses.append({"severity": {"$eq": severity_filter.lower()}})
    if exclude_fp:
        where_clauses.append({"is_false_positive": {"$eq": "False"}})

    where = None
    if len(where_clauses) == 1:
        where = where_clauses[0]
    elif len(where_clauses) > 1:
        where = {"$and": where_clauses}

    results = collection.query(
        query_texts=[code_or_description],
        n_results=n_results,
        where=where,
        include=["documents", "metadatas", "distances"],
    )
    return _format_results(results)


def query_by_category(
    protocol_type: str,
    vuln_class: str,
    n_results: int = 5,
    severity_filter: Optional[str] = None,
    db_path: str = DEFAULT_DB,
) -> List[Dict]:
    """
    Pass 2 — Category query.
    Use for broad surface coverage questions.
    Example: protocol_type="fixed-rate-lending", vuln_class="arithmetic rounding"
    """
    collection = _get_collection(db_path)
    query_text = f"{protocol_type} {vuln_class} vulnerability exploit"

    where = None
    if protocol_type and protocol_type != "any":
        if severity_filter:
            where = {"$and": [
                {"protocol_type": {"$eq": protocol_type}},
                {"severity":      {"$eq": severity_filter.lower()}},
            ]}
        else:
            where = {"protocol_type": {"$eq": protocol_type}}
    elif severity_filter:
        where = {"severity": {"$eq": severity_filter.lower()}}

    results = collection.query(
        query_texts=[query_text],
        n_results=n_results,
        where=where,
        include=["documents", "metadatas", "distances"],
    )
    return _format_results(results)


def query_false_positives(
    pattern_description: str,
    n_results: int = 3,
    db_path: str = DEFAULT_DB,
) -> List[Dict]:
    """
    Pass 3 — False positive check. Run this BEFORE writing a PoC.
    Finds documented cases that looked like the pattern but weren't exploitable.
    """
    collection = _get_collection(db_path)
    query_text = (
        f"false positive not exploitable safe by design {pattern_description}"
    )
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results,
        where={"is_false_positive": {"$eq": "True"}},
        include=["documents", "metadatas", "distances"],
    )
    return _format_results(results)


def query_all_high_medium(
    n_results: int = 20,
    db_path: str = DEFAULT_DB,
) -> List[Dict]:
    """Get all H/M findings across the corpus. Good for broad surface awareness."""
    collection = _get_collection(db_path)
    results = collection.query(
        query_texts=["high medium severity vulnerability exploit critical"],
        n_results=n_results,
        where={"$and": [
            {"severity":         {"$in": ["critical", "high", "medium"]}},
            {"is_false_positive": {"$eq": "False"}},
        ]},
        include=["documents", "metadatas", "distances"],
    )
    return _format_results(results)


# ── Display ──────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "\033[95m",  # magenta
    "high":     "\033[91m",  # red
    "medium":   "\033[93m",  # yellow
    "low":      "\033[94m",  # blue
    "info":     "\033[96m",  # cyan
    "unknown":  "\033[90m",  # grey
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def print_results(results: List[Dict], truncate: int = 600):
    if not results:
        print("\n  No results found.\n")
        return

    for i, r in enumerate(results, 1):
        sev   = r["severity"].upper()
        color = SEVERITY_COLORS.get(r["severity"], "")
        fp_tag = f"  {BOLD}[FALSE POSITIVE]{RESET}" if r["is_fp"] else ""
        code_tag = " 📎" if r["has_code"] else ""
        sim = f"  {r['similarity']:.1%}" if r["similarity"] else ""

        print(f"\n{'─'*60}")
        print(
            f"  {BOLD}[{i}]{RESET} "
            f"{color}{BOLD}{sev}{RESET} | "
            f"{r['protocol']} ({r['protocol_type']}) | "
            f"{r['category']}{code_tag}{fp_tag}{sim}"
        )

        text = r["text"]
        if len(text) > truncate:
            text = text[:truncate] + f"\n  ... [{len(r['text']) - truncate} chars truncated]"
        for line in text.splitlines():
            print(f"  {line}")

    print(f"\n{'─'*60}")
    print(f"  {len(results)} result(s)\n")


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Query the audit findings RAG",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Pass 1: structural pattern
  python3 rag/query.py --pattern "callback before state write ERC20 transfer"

  # Pass 2: category
  python3 rag/query.py --category "fixed-rate-lending arithmetic rounding"

  # Pass 3: false positive check (run BEFORE writing PoC)
  python3 rag/query.py --fp "reentrancy callback during liquidation"

  # All H/M findings in corpus
  python3 rag/query.py --all-hm

  # Filter by severity
  python3 rag/query.py --pattern "domain separator" --severity high
        """,
    )
    parser.add_argument("--pattern",   help="Code snippet or structural pattern (Pass 1)")
    parser.add_argument("--category",  help="'<protocol-type> <vuln-class>' (Pass 2)")
    parser.add_argument("--fp",        help="False positive check for this pattern (Pass 3)")
    parser.add_argument("--all-hm",    action="store_true", help="List all H/M findings")
    parser.add_argument("--severity",  help="Filter: critical/high/medium/low/info")
    parser.add_argument("--n",         type=int, default=5, help="Number of results (default 5)")
    parser.add_argument("--full",      action="store_true", help="Show full finding text (no truncation)")
    parser.add_argument("--db",        default=DEFAULT_DB, help=f"ChromaDB path (default: {DEFAULT_DB})")
    args = parser.parse_args()

    truncate = 99999 if args.full else 600

    if args.pattern:
        print(f"\nPass 1 — Pattern: {args.pattern[:80]}")
        results = query_by_pattern(args.pattern, args.n, args.severity, db_path=args.db)
        print_results(results, truncate)

    elif args.category:
        parts = args.category.split(None, 1)
        ptype = parts[0]
        vclass = parts[1] if len(parts) > 1 else parts[0]
        print(f"\nPass 2 — Category: {ptype} × {vclass}")
        results = query_by_category(ptype, vclass, args.n, args.severity, args.db)
        print_results(results, truncate)

    elif args.fp:
        print(f"\nPass 3 — False positive check: {args.fp[:80]}")
        results = query_false_positives(args.fp, args.n, args.db)
        print_results(results, truncate)

    elif args.all_hm:
        print("\nAll H/M findings in corpus:")
        results = query_all_high_medium(args.n, args.db)
        print_results(results, truncate)

    else:
        parser.print_help()
