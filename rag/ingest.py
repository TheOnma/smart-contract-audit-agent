"""
Ingest audit reports into ChromaDB.
Chunking strategy: one chunk per finding (not per page).
Supports PDF, markdown, and plain text.

Usage:
    python3 rag/ingest.py --corpus rag/corpus --db .rag/db
"""
import chromadb
import os
import re
import json
import argparse
from pathlib import Path
from typing import List, Dict

try:
    import pdfplumber
    HAS_PDF = True
except ImportError:
    HAS_PDF = False


# ── Severity / category detection ──────────────────────────────────────────

SEVERITY_KEYWORDS = {
    "critical": ["critical", "[c-"],
    "high":     ["[h-", "high severity", "high risk", "severity: high"],
    "medium":   ["[m-", "medium severity", "medium risk", "severity: medium"],
    "low":      ["[l-", "low severity", "low risk", "severity: low"],
    "info":     ["[i-", "informational", "severity: info", "gas"],
}

CATEGORY_KEYWORDS = {
    "reentrancy":      ["reentran", "callback reuse", "cross-function reentran"],
    "arithmetic":      ["overflow", "underflow", "rounding", "precision", "muldiv", "division"],
    "access_control":  ["authorization", "auth bypass", "permission", "unauthorized", "onlyrole"],
    "oracle":          ["oracle", "price manipulation", "price feed", "stale price"],
    "economic":        ["incentive", "economic attack", "arbitrage", "profit", "front-run"],
    "replay":          ["replay", "domain separator", "nonce reuse", "signature reuse"],
    "dos":             ["denial of service", "dos", "lock", "freeze", "grief", "stuck"],
    "logic":           ["logic error", "invariant", "state inconsisten", "accounting"],
    "flash_loan":      ["flash loan", "flashloan", "flash borrow"],
}


def detect_severity(text: str) -> str:
    sample = text[:300].lower()
    for sev, keywords in SEVERITY_KEYWORDS.items():
        if any(kw in sample for kw in keywords):
            return sev
    return "unknown"


def detect_category(text: str) -> str:
    body = text.lower()
    for cat, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in body for kw in keywords):
            return cat
    return "logic"  # default


# ── Text extraction ─────────────────────────────────────────────────────────

def extract_text_from_pdf(path: str) -> str:
    if not HAS_PDF:
        raise ImportError(
            "pdfplumber not installed. Run: pip install pdfplumber"
        )
    with pdfplumber.open(path) as pdf:
        pages = [page.extract_text() or "" for page in pdf.pages]
    return "\n".join(pages)


def extract_text_from_file(path: Path) -> str:
    if path.suffix == ".pdf":
        return extract_text_from_pdf(str(path))
    return path.read_text(encoding="utf-8", errors="replace")


# ── Chunking ────────────────────────────────────────────────────────────────

# Patterns that signal the start of a new finding
_FINDING_HEADER = re.compile(
    r"(?m)^#{1,4}\s+"
    r"(?:"
    r"\[?[HMSLICG][-\s]?\d+\]?"      # [H-01], M-02, L03
    r"|(?:Critical|High|Medium|Low|Info|Gas)\s*[-–:]?\s*\d*"
    r"|Finding\s+\d+"
    r"|Issue\s+\d+"
    r"|Bug\s+\d+"
    r"|Vulnerability\s+\d+"
    r")",
    re.IGNORECASE,
)


def chunk_by_finding(
    text: str,
    protocol_name: str,
    protocol_type: str,
    source_file: str,
    is_false_positive_file: bool = False,
) -> List[Dict]:
    """Split audit report into one chunk per finding."""
    # Find all header positions
    positions = [m.start() for m in _FINDING_HEADER.finditer(text)]

    if not positions:
        # No structured findings found — treat whole document as one chunk
        if len(text.strip()) > 200:
            return [_make_chunk(text, protocol_name, protocol_type,
                                source_file, is_false_positive_file)]
        return []

    # Split into sections at each header
    sections = []
    for i, pos in enumerate(positions):
        end = positions[i + 1] if i + 1 < len(positions) else len(text)
        sections.append(text[pos:end])

    chunks = []
    for section in sections:
        if len(section.strip()) < 150:
            continue
        chunks.append(_make_chunk(
            section, protocol_name, protocol_type,
            source_file, is_false_positive_file,
        ))

    return chunks


def _make_chunk(
    text: str,
    protocol_name: str,
    protocol_type: str,
    source_file: str,
    is_false_positive: bool,
) -> Dict:
    code_blocks = re.findall(
        r"```(?:solidity|sol|vyper)?\n(.*?)```", text, re.DOTALL
    )
    return {
        "text": text.strip(),
        "protocol_name": protocol_name,
        "protocol_type": protocol_type,
        "severity": detect_severity(text),
        "category": detect_category(text),
        "has_code": len(code_blocks) > 0,
        "is_false_positive": is_false_positive,
        "source_file": source_file,
    }


# ── Ingestion ───────────────────────────────────────────────────────────────

def ingest_file(
    collection,
    file_path: Path,
    protocol_name: str,
    protocol_type: str,
) -> int:
    is_fp = "false-positive" in file_path.name or "false_positive" in file_path.name

    try:
        text = extract_text_from_file(file_path)
    except Exception as e:
        print(f"    ERROR reading {file_path.name}: {e}")
        return 0

    chunks = chunk_by_finding(
        text, protocol_name, protocol_type, str(file_path), is_fp
    )

    if not chunks:
        print(f"    No findings extracted from {file_path.name}")
        return 0

    ids, documents, metadatas = [], [], []
    for i, chunk in enumerate(chunks):
        doc_id = f"{protocol_name.lower().replace(' ', '_')}_{file_path.stem}_{i}"
        ids.append(doc_id)
        documents.append(chunk["text"])
        metadatas.append({
            "protocol_name": chunk["protocol_name"],
            "protocol_type": chunk["protocol_type"],
            "severity":       chunk["severity"],
            "category":       chunk["category"],
            "has_code":       str(chunk["has_code"]),
            "is_false_positive": str(chunk["is_false_positive"]),
            "source_file":    chunk["source_file"],
        })

    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
    label = " [FALSE POSITIVES]" if is_fp else ""
    print(f"    {len(chunks):3d} findings{label} ← {file_path.name}")
    return len(chunks)


def ingest_corpus(corpus_dir: str, db_path: str = ".rag/db") -> int:
    """Walk corpus_dir and ingest all protocol subdirectories."""
    os.makedirs(db_path, exist_ok=True)
    client = chromadb.PersistentClient(path=db_path)
    collection = client.get_or_create_collection(
        name="audit_findings",
        metadata={"hnsw:space": "cosine"},
    )

    corpus_path = Path(corpus_dir)
    if not corpus_path.exists():
        print(f"ERROR: Corpus directory not found: {corpus_dir}")
        return 0

    total = 0

    for protocol_dir in sorted(corpus_path.iterdir()):
        if not protocol_dir.is_dir():
            continue

        meta_file = protocol_dir / "meta.json"
        if meta_file.exists():
            meta = json.loads(meta_file.read_text())
            protocol_name = meta.get("name", protocol_dir.name)
            protocol_type = meta.get("type", "lending")
        else:
            protocol_name = protocol_dir.name
            protocol_type = "lending"

        print(f"\n  [{protocol_type}] {protocol_name}")

        for report_file in sorted(protocol_dir.rglob("*")):
            if report_file.is_file() and report_file.suffix in (".pdf", ".md", ".txt"):
                count = ingest_file(collection, report_file, protocol_name, protocol_type)
                total += count

    print(f"\n  Total findings ingested : {total}")
    print(f"  Collection size          : {collection.count()}")
    return total


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest audit reports into RAG")
    parser.add_argument("--corpus", default="rag/corpus", help="Corpus directory")
    parser.add_argument("--db",     default=".rag/db",    help="ChromaDB path")
    parser.add_argument("--project", default="",          help="Target project (for logging)")
    args = parser.parse_args()

    if args.project:
        print(f"Initializing RAG for project: {args.project}")
    ingest_corpus(args.corpus, args.db)
