"""
Query the audit findings RAG (OpenAI embeddings).
Three-pass strategy:
  Pass 1 --pattern  : structural code pattern match
  Pass 2 --category : protocol type × vulnerability class
  Pass 3 --fp       : false-positive check (run BEFORE writing a PoC)

Usage:
    python3 rag/query.py --pattern "mulDivDown rounding lossFactor saturation"
    python3 rag/query.py --category "fixed-rate-lending arithmetic"
    python3 rag/query.py --fp "lossFactor update rounding toward zero"
    python3 rag/query.py --all-hm --n 20
"""
import chromadb
import argparse
import os
import sys
from pathlib import Path
from typing import List, Dict, Optional
from dotenv import load_dotenv
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction

DEFAULT_DB = ".rag/db"


# ── Key loading ─────────────────────────────────────────────────────────────

def load_openai_key(env_path: str) -> str:
    load_dotenv(env_path)
    key = (
        os.getenv("OPENAI-KEY")
        or os.getenv("OPENAI_KEY")
        or os.getenv("OPENAI_API_KEY")
    )
    if not key:
        raise ValueError(f"No OpenAI key found in {env_path}.")
    return key


def get_embedding_function(openai_key: str) -> OpenAIEmbeddingFunction:
    return OpenAIEmbeddingFunction(
        api_key=openai_key,
        model_name="text-embedding-3-small",
    )


# ── Collection helper ────────────────────────────────────────────────────────

def _get_collection(db_path: str, openai_key: str):
    try:
        client = chromadb.PersistentClient(path=db_path)
        ef = get_embedding_function(openai_key)
        return client.get_collection("audit_findings", embedding_function=ef)
    except Exception:
        print(f"ERROR: No RAG database found at {db_path}")
        print("Run: python3 rag/ingest.py --corpus /path/to/Documents_for_rag")
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
            "id":            doc_id,
            "protocol":      meta.get("protocol_name", "?"),
            "protocol_type": meta.get("protocol_type", "?"),
            "severity":      meta.get("severity", "?"),
            "category":      meta.get("category", "?"),
            "is_fp":         meta.get("is_false_positive", "False") == "True",
            "has_code":      meta.get("has_code", "False") == "True",
            "similarity":    round(1 - distance, 3) if distance is not None else None,
            "text":          text,
            "source":        meta.get("source_file", ""),
        })
    return out


# ── Query functions ──────────────────────────────────────────────────────────

def query_by_pattern(
    code_or_description: str,
    n_results: int = 5,
    severity_filter: Optional[str] = None,
    db_path: str = DEFAULT_DB,
    openai_key: str = "",
) -> List[Dict]:
    """Pass 1: Find findings with similar code patterns or structural descriptions."""
    collection = _get_collection(db_path, openai_key)

    where = None
    if severity_filter:
        where = {"severity": {"$eq": severity_filter.lower()}}

    return _format_results(collection.query(
        query_texts=[code_or_description],
        n_results=n_results,
        where=where,
        include=["documents", "metadatas", "distances"],
    ))


def query_by_category(
    protocol_type: str,
    vuln_class: str,
    n_results: int = 5,
    severity_filter: Optional[str] = None,
    db_path: str = DEFAULT_DB,
    openai_key: str = "",
) -> List[Dict]:
    """Pass 2: Find findings by protocol type × vulnerability class."""
    collection = _get_collection(db_path, openai_key)
    query_text = f"{protocol_type} {vuln_class} vulnerability exploit"

    where_clauses = []
    if protocol_type and protocol_type != "any":
        where_clauses.append({"protocol_type": {"$eq": protocol_type}})
    if severity_filter:
        where_clauses.append({"severity": {"$eq": severity_filter.lower()}})

    where = None
    if len(where_clauses) == 1:
        where = where_clauses[0]
    elif len(where_clauses) > 1:
        where = {"$and": where_clauses}

    return _format_results(collection.query(
        query_texts=[query_text],
        n_results=n_results,
        where=where,
        include=["documents", "metadatas", "distances"],
    ))


def query_false_positives(
    pattern_description: str,
    n_results: int = 3,
    db_path: str = DEFAULT_DB,
    openai_key: str = "",
) -> List[Dict]:
    """Pass 3: Find documented false positives similar to a hypothesis. Run BEFORE writing a PoC."""
    collection = _get_collection(db_path, openai_key)
    query_text = f"false positive not exploitable safe by design {pattern_description}"

    return _format_results(collection.query(
        query_texts=[query_text],
        n_results=n_results,
        where={"is_false_positive": {"$eq": "True"}},
        include=["documents", "metadatas", "distances"],
    ))


def query_all_high_medium(
    n_results: int = 20,
    db_path: str = DEFAULT_DB,
    openai_key: str = "",
) -> List[Dict]:
    """Return all H/M findings across the corpus for broad surface awareness."""
    collection = _get_collection(db_path, openai_key)
    return _format_results(collection.query(
        query_texts=["high medium severity vulnerability critical exploit"],
        n_results=n_results,
        where={"$and": [
            {"severity":          {"$in": ["critical", "high", "medium"]}},
            {"is_false_positive": {"$eq": "False"}},
        ]},
        include=["documents", "metadatas", "distances"],
    ))


# ── Display ──────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "\033[95m",
    "high":     "\033[91m",
    "medium":   "\033[93m",
    "low":      "\033[94m",
    "info":     "\033[96m",
    "unknown":  "\033[90m",
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
        fp    = f"  {BOLD}[FALSE POSITIVE]{RESET}" if r["is_fp"] else ""
        code  = " 📎" if r["has_code"] else ""
        sim   = f"  {r['similarity']:.1%}" if r["similarity"] else ""

        print(f"\n{'─'*60}")
        print(f"  {BOLD}[{i}]{RESET} {color}{BOLD}{sev}{RESET} | "
              f"{r['protocol']} ({r['protocol_type']}) | {r['category']}{code}{fp}{sim}")

        text = r["text"]
        if len(text) > truncate:
            text = text[:truncate] + f"\n  ... [{len(r['text']) - truncate} chars truncated]"
        for line in text.splitlines():
            print(f"  {line}")

    print(f"\n{'─'*60}")
    print(f"  {len(results)} result(s)\n")


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    default_env = str(Path(__file__).parent.parent / ".env")

    parser = argparse.ArgumentParser(
        description="Query audit findings RAG (OpenAI embeddings)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Pass 1: what bugs look like this code pattern?
  python3 rag/query.py --pattern "mulDivDown rounding lossFactor saturation"

  # Pass 2: what H/M findings exist for this protocol type?
  python3 rag/query.py --category "fixed-rate-lending arithmetic" --severity high

  # Pass 3: is this hypothesis a known false positive?
  python3 rag/query.py --fp "lossFactor rounding toward zero"

  # All H/M findings in corpus
  python3 rag/query.py --all-hm --n 20
        """,
    )
    parser.add_argument("--pattern",  help="Code snippet or structural pattern (Pass 1)")
    parser.add_argument("--category", help="'<protocol-type> <vuln-class>' (Pass 2)")
    parser.add_argument("--fp",       help="False-positive check for this pattern (Pass 3)")
    parser.add_argument("--all-hm",   action="store_true", help="List all H/M findings")
    parser.add_argument("--severity", help="Filter: critical/high/medium/low/info")
    parser.add_argument("--n",        type=int, default=5, help="Number of results (default 5)")
    parser.add_argument("--full",     action="store_true", help="Show full text (no truncation)")
    parser.add_argument("--db",       default=DEFAULT_DB,  help=f"ChromaDB path (default: {DEFAULT_DB})")
    parser.add_argument("--env",      default=default_env, help="Path to .env with OPENAI-KEY")
    args = parser.parse_args()

    openai_key = load_openai_key(args.env)
    truncate   = 99999 if args.full else 600

    if args.pattern:
        print(f"\nPass 1 — Pattern: {args.pattern[:80]}")
        results = query_by_pattern(args.pattern, args.n, args.severity, args.db, openai_key)
        print_results(results, truncate)

    elif args.category:
        parts  = args.category.split(None, 1)
        ptype  = parts[0]
        vclass = parts[1] if len(parts) > 1 else parts[0]
        print(f"\nPass 2 — Category: {ptype} × {vclass}")
        results = query_by_category(ptype, vclass, args.n, args.severity, args.db, openai_key)
        print_results(results, truncate)

    elif args.fp:
        print(f"\nPass 3 — False positive check: {args.fp[:80]}")
        results = query_false_positives(args.fp, args.n, args.db, openai_key)
        print_results(results, truncate)

    elif args.all_hm:
        print("\nAll H/M findings in corpus:")
        results = query_all_high_medium(args.n, args.db, openai_key)
        print_results(results, truncate)

    else:
        parser.print_help()
