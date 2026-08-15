"""
Ingest audit reports into ChromaDB using OpenAI embeddings.
Chunking strategy: one chunk per finding (not per page).
Supports PDF, markdown, and plain text. Walks directories recursively.

Usage:
    python3 rag/ingest.py --corpus /path/to/Documents_for_rag
    python3 rag/ingest.py --corpus rag/corpus --env /path/to/.env
"""
import chromadb
import os
import re
import json
import argparse
from pathlib import Path
from typing import List, Dict
from dotenv import load_dotenv
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction

try:
    import pdfplumber
    HAS_PDF = True
except ImportError:
    HAS_PDF = False


# ── OpenAI key + embedding function ────────────────────────────────────────

def load_openai_key(env_path: str) -> str:
    load_dotenv(env_path)
    key = (
        os.getenv("OPENAI-KEY")
        or os.getenv("OPENAI_KEY")
        or os.getenv("OPENAI_API_KEY")
    )
    if not key:
        raise ValueError(
            f"No OpenAI key found in {env_path}. "
            "Expected OPENAI-KEY, OPENAI_KEY, or OPENAI_API_KEY."
        )
    return key


def get_embedding_function(openai_key: str) -> OpenAIEmbeddingFunction:
    return OpenAIEmbeddingFunction(
        api_key=openai_key,
        model_name="text-embedding-3-small",
    )


# ── Severity / category detection ──────────────────────────────────────────

SEVERITY_KEYWORDS = {
    "critical": ["critical", "[c-", "[critical]", "[c]"],
    "high":     ["[h-", "high severity", "high risk", "severity: high", "[high]"],
    "medium":   ["[m-", "medium severity", "medium risk", "severity: medium", "[medium]"],
    "low":      ["[l-", "low severity", "low risk", "severity: low", "[low]"],
    "info":     ["[i-", "informational", "severity: info", "gas", "[info]", "[gas]"],
}

CATEGORY_KEYWORDS = {
    "reentrancy":     ["reentran", "callback reuse", "cross-function"],
    "arithmetic":     ["overflow", "underflow", "rounding", "precision", "muldiv", "division"],
    "access_control": ["authorization", "auth bypass", "permission", "unauthorized"],
    "oracle":         ["oracle", "price manipulation", "price feed", "stale price"],
    "economic":       ["incentive", "economic attack", "arbitrage", "profit", "front-run"],
    "replay":         ["replay", "domain separator", "nonce reuse", "signature reuse"],
    "dos":            ["denial of service", "dos", "lock", "freeze", "grief", "stuck"],
    "flash_loan":     ["flash loan", "flashloan", "flash borrow"],
    "logic":          ["logic error", "invariant", "state inconsisten", "accounting"],
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
    return "logic"


# ── Text extraction ─────────────────────────────────────────────────────────

def extract_text(path: Path) -> str:
    if path.suffix == ".pdf":
        if not HAS_PDF:
            raise ImportError("pdfplumber not installed. Run: pip install pdfplumber")
        with pdfplumber.open(str(path)) as pdf:
            return "\n".join(page.extract_text() or "" for page in pdf.pages)
    return path.read_text(encoding="utf-8", errors="replace")


# ── Chunking ────────────────────────────────────────────────────────────────

# OpenAI text-embedding-3-small has an 8192 token limit.
# PDF text is often dense — use 4000 chars (~1000 tokens) as a safe ceiling.
MAX_CHUNK_CHARS = 4_000

_FINDING_HEADER = re.compile(
    r"(?m)^#{1,4}\s+"
    r"(?:"
    # C4 / Solodit: ## [[H-02] Title](url) or ## [M-01] Title
    r"\[?\[?[HMCIL]-\d+\]?"
    # Cantina: ## [MEDIUM] M-3 Title, ## [LOW], ## [GAS] G-1
    r"|\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO|GAS)\]\s*[HMCILG]?-?\d*"
    # Section headers: # High Risk Findings (8)
    r"|(?:Critical|High|Medium|Low|Info|Gas)\s*(?:Risk|Severity|Findings)?\s*[-–:]?\s*\d*"
    r"|Finding\s+\d+"
    r"|Issue\s+\d+"
    r"|Bug\s+\d+"
    r"|Vulnerability\s+\d+"
    r")",
    re.IGNORECASE,
)


def _split_large(text: str, max_chars: int = MAX_CHUNK_CHARS) -> List[str]:
    """Split text into pieces no larger than max_chars, breaking on paragraphs or lines."""
    if len(text) <= max_chars:
        return [text]

    # Try paragraph breaks first (double newline), fall back to single newline
    separators = [r"\n{2,}", r"\n", r"(?<=[.!?])\s+"]
    units: List[str] = [text]
    for sep in separators:
        units = re.split(sep, text)
        if len(units) > 1:
            break

    pieces: List[str] = []
    current: List[str] = []
    current_len = 0

    for unit in units:
        if current_len + len(unit) > max_chars and current:
            pieces.append(" ".join(current))
            current, current_len = [], 0
        # If a single unit is still too large, hard-split it by character
        if len(unit) > max_chars:
            for i in range(0, len(unit), max_chars):
                pieces.append(unit[i:i + max_chars])
        else:
            current.append(unit)
            current_len += len(unit)

    if current:
        pieces.append(" ".join(current))

    return [p for p in pieces if len(p.strip()) > 50]


def chunk_by_finding(
    text: str,
    protocol_name: str,
    protocol_type: str,
    source_file: str,
    is_false_positive: bool = False,
) -> List[Dict]:
    positions = [m.start() for m in _FINDING_HEADER.finditer(text)]

    if not positions:
        # No structured findings — split by size and chunk the whole doc
        chunks = []
        for piece in _split_large(text):
            if len(piece.strip()) > 200:
                chunks.append(_make_chunk(piece, protocol_name, protocol_type, source_file, is_false_positive))
        return chunks

    chunks = []
    for i, pos in enumerate(positions):
        end = positions[i + 1] if i + 1 < len(positions) else len(text)
        section = text[pos:end]
        if len(section.strip()) < 150:
            continue
        # If a single finding is still too large, split it further
        for piece in _split_large(section):
            chunks.append(_make_chunk(piece, protocol_name, protocol_type, source_file, is_false_positive))

    return chunks


def _make_chunk(text, protocol_name, protocol_type, source_file, is_false_positive):
    code_blocks = re.findall(r"```(?:solidity|sol|vyper)?\n(.*?)```", text, re.DOTALL)
    return {
        "text":              text.strip(),
        "protocol_name":     protocol_name,
        "protocol_type":     protocol_type,
        "severity":          detect_severity(text),
        "category":          detect_category(text),
        "has_code":          len(code_blocks) > 0,
        "is_false_positive": is_false_positive,
        "source_file":       source_file,
    }


# ── Per-file ingest ─────────────────────────────────────────────────────────

def ingest_file(collection, file_path: Path, protocol_name: str, protocol_type: str) -> int:
    is_fp = "false-positive" in file_path.name or "false_positive" in file_path.name

    try:
        text = extract_text(file_path)
    except Exception as e:
        print(f"    ERROR reading {file_path.name}: {e}")
        return 0

    chunks = chunk_by_finding(text, protocol_name, protocol_type, str(file_path), is_fp)
    if not chunks:
        print(f"    (0 findings found)  {file_path.name}")
        return 0

    safe = re.sub(r"[^a-z0-9]", "_", protocol_name.lower())
    ids, documents, metadatas = [], [], []
    for i, c in enumerate(chunks):
        ids.append(f"{safe}__{file_path.stem[:40]}__{i}")
        documents.append(c["text"])
        metadatas.append({
            "protocol_name":     c["protocol_name"],
            "protocol_type":     c["protocol_type"],
            "severity":          c["severity"],
            "category":          c["category"],
            "has_code":          str(c["has_code"]),
            "is_false_positive": str(c["is_false_positive"]),
            "source_file":       c["source_file"],
        })

    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
    fp_tag = " [FP]" if is_fp else ""
    print(f"    {len(chunks):3d} chunks{fp_tag}  ←  {file_path.name}")
    return len(chunks)


# ── Infer protocol type from directory name ─────────────────────────────────

def _infer_type(name: str) -> str:
    n = name.lower()
    if any(w in n for w in ["notional", "pendle", "term", "midnight", "element", "sense", "fixed"]):
        return "fixed-rate-lending"
    if any(w in n for w in ["morpho", "euler", "aave", "compound", "maker", "spark"]):
        return "lending"
    if any(w in n for w in ["uniswap", "curve", "amm", "dex", "balancer"]):
        return "amm"
    return "lending"


# ── Corpus walking (recursive — any depth) ─────────────────────────────────

def ingest_corpus(corpus_dir: str, db_path: str, openai_key: str) -> int:
    os.makedirs(db_path, exist_ok=True)
    client = chromadb.PersistentClient(path=db_path)
    ef     = get_embedding_function(openai_key)

    # Always rebuild the collection so the embedding function is fresh
    try:
        client.delete_collection("audit_findings")
        print("  Cleared existing collection.")
    except Exception:
        pass

    collection = client.create_collection(
        name="audit_findings",
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    corpus_path = Path(corpus_dir)
    if not corpus_path.exists():
        print(f"ERROR: corpus directory not found: {corpus_dir}")
        return 0

    # Find every SUBDIRECTORY that contains at least one supported document.
    # Skip the corpus root itself — root-level files have no protocol context.
    doc_extensions = {".pdf", ".md", ".txt"}
    all_dirs = sorted({
        f.parent
        for f in corpus_path.rglob("*")
        if (
            f.is_file()
            and f.suffix in doc_extensions
            and ".DS_Store" not in str(f)
            and f.parent != corpus_path          # skip root-level files
        )
    })

    total = 0
    for doc_dir in all_dirs:
        meta_file = doc_dir / "meta.json"
        if meta_file.exists():
            meta          = json.loads(meta_file.read_text())
            protocol_name = meta.get("name", doc_dir.name)
            protocol_type = meta.get("type", _infer_type(doc_dir.name))
        else:
            protocol_name = doc_dir.name.replace("_", " ").replace("-", " ").title()
            protocol_type = _infer_type(doc_dir.name)

        print(f"\n  [{protocol_type}]  {protocol_name}")

        for f in sorted(doc_dir.iterdir()):
            if f.is_file() and f.suffix in doc_extensions:
                total += ingest_file(collection, f, protocol_name, protocol_type)

    print(f"\n  ✓  Total chunks ingested : {total}")
    print(f"  ✓  Collection size        : {collection.count()}")
    return total


# ── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Default .env path: look in the agent repo root (where this script lives)
    default_env = str(Path(__file__).parent.parent / ".env")

    parser = argparse.ArgumentParser(description="Ingest audit reports → ChromaDB (OpenAI embeddings)")
    parser.add_argument("--corpus",  default="rag/corpus",  help="Corpus directory path")
    parser.add_argument("--db",      default=".rag/db",     help="ChromaDB database path")
    parser.add_argument("--env",     default=default_env,   help="Path to .env with OPENAI-KEY")
    parser.add_argument("--project", default="",            help="Project name (for logging)")
    args = parser.parse_args()

    if args.project:
        print(f"Project: {args.project}")

    print(f"Loading OpenAI key from: {args.env}")
    openai_key = load_openai_key(args.env)
    print(f"  Key loaded: {openai_key[:16]}...")

    print(f"\nIngesting corpus: {args.corpus}")
    ingest_corpus(args.corpus, args.db, openai_key)
