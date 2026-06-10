#!/usr/bin/env bash
# init.sh — Initialize smart-contract-audit-agent for a target project
# Usage: ./init.sh /path/to/target-project

set -euo pipefail

TARGET="${1:?Usage: ./init.sh /path/to/target-project}"
AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_RAG="$AGENT_DIR/.rag/db"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     Smart Contract Audit Agent — Init            ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "  Target:    $TARGET"
echo "  Agent dir: $AGENT_DIR"
echo ""

# ── 1. Validate target ──────────────────────────────────────────────────────

if [[ ! -d "$TARGET" ]]; then
  echo "ERROR: Target directory does not exist: $TARGET"
  exit 1
fi

PROJECT_CLAUDE="$TARGET/CLAUDE.md"
if [[ ! -f "$PROJECT_CLAUDE" ]]; then
  echo "⚠  WARNING: No CLAUDE.md found at $PROJECT_CLAUDE"
  echo "   Consider running the /x-ray skill first to generate one."
  echo "   Continuing without project context..."
  echo ""
fi

# Detect if target has a Foundry setup
if [[ -f "$TARGET/foundry.toml" ]]; then
  echo "✓  Foundry project detected"
else
  echo "⚠  No foundry.toml found — fuzzing templates may need adjustment"
fi

# ── 2. Create audit directories ─────────────────────────────────────────────

mkdir -p "$TARGET/test/audit"
mkdir -p "$TARGET/test/formal"
mkdir -p "$TARGET/.audit/findings"
mkdir -p "$TARGET/certora/audit_rules"

echo "✓  Created audit directories"

# ── 3. Copy fuzzing templates ────────────────────────────────────────────────

for template in "$AGENT_DIR/fuzzing/templates/"*.sol; do
  fname="$(basename "$template")"
  dest="$TARGET/test/audit/$fname"
  if [[ -f "$dest" ]]; then
    echo "   Skipping $fname (already exists)"
  else
    cp "$template" "$dest"
    echo "   Copied: test/audit/$fname"
  fi
done

# Copy Echidna config (don't overwrite existing)
if [[ -f "$AGENT_DIR/fuzzing/echidna.yaml" && ! -f "$TARGET/echidna.yaml" ]]; then
  cp "$AGENT_DIR/fuzzing/echidna.yaml" "$TARGET/echidna.yaml"
  echo "   Copied: echidna.yaml"
fi

echo "✓  Fuzzing templates installed"

# ── 4. Copy formal verification templates ───────────────────────────────────

for halmos_file in "$AGENT_DIR/formal/halmos/"*.sol; do
  [[ -f "$halmos_file" ]] || continue
  fname="$(basename "$halmos_file")"
  dest="$TARGET/test/formal/$fname"
  if [[ ! -f "$dest" ]]; then
    cp "$halmos_file" "$dest"
    echo "   Copied: test/formal/$fname"
  fi
done

for certora_rule in "$AGENT_DIR/formal/certora/rule_templates/"*.spec; do
  [[ -f "$certora_rule" ]] || continue
  fname="$(basename "$certora_rule")"
  dest="$TARGET/certora/audit_rules/$fname"
  if [[ ! -f "$dest" ]]; then
    cp "$certora_rule" "$dest"
    echo "   Copied: certora/audit_rules/$fname"
  fi
done

echo "✓  Formal verification templates installed"

# ── 5. Build RAG index ───────────────────────────────────────────────────────

CORPUS_DIR="$AGENT_DIR/rag/corpus"
CORPUS_COUNT=$(find "$CORPUS_DIR" -type f \( -name "*.pdf" -o -name "*.md" -o -name "*.txt" \) | wc -l | tr -d ' ')

if [[ "$CORPUS_COUNT" -gt 0 ]]; then
  echo ""
  echo "Building RAG index from $CORPUS_COUNT corpus files..."
  python3 "$AGENT_DIR/rag/ingest.py" \
    --corpus "$CORPUS_DIR" \
    --db "$AGENT_RAG" \
    --project "$(basename "$TARGET")" \
    || echo "⚠  RAG build failed — check python3 and dependencies (pip install -r requirements.txt)"
  echo "✓  RAG index built at $AGENT_RAG"
else
  echo "⚠  No corpus files found in $CORPUS_DIR"
  echo "   Add audit reports (PDF/markdown) to rag/corpus/<protocol-name>/"
  echo "   See rag/corpus/sources.md for where to get them"
fi

# ── 6. Write project config ──────────────────────────────────────────────────

CONFIG_FILE="$TARGET/.audit/agent-config.json"
cat > "$CONFIG_FILE" << EOF
{
  "project": "$(basename "$TARGET")",
  "target_path": "$TARGET",
  "agent_dir": "$AGENT_DIR",
  "rag_db": "$AGENT_RAG",
  "initialized_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "templates_installed": {
    "fuzzing": true,
    "halmos": true,
    "certora": true
  }
}
EOF

echo "✓  Agent config written to .audit/agent-config.json"

# ── 7. Print next steps ──────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Setup complete. Next steps:                     ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "  1. Fill in TODOs in test/audit/InvariantHarness.t.sol"
echo "     (protocol contracts, ghost state, actor setup)"
echo ""
echo "  2. Run unit property tests:"
echo "     cd $TARGET"
echo "     forge test --match-path 'test/audit/UnitPropertyTests.t.sol' --fuzz-runs 100000 -vv"
echo ""
echo "  3. Query RAG for analogous findings:"
echo "     python3 $AGENT_DIR/rag/query.py --pattern 'callback before state write'"
echo "     python3 $AGENT_DIR/rag/query.py --category 'fixed-rate-lending arithmetic'"
echo ""
echo "  4. Run Halmos (after filling in MonotonicityCheck.t.sol):"
echo "     cd $TARGET"
echo "     halmos --contract MonotonicityCheck --function check_yourProperty --loop 3"
echo ""
echo "  5. Run Echidna with corpus seeding:"
echo "     cd $TARGET"
echo "     echidna . --contract InvariantHarness --config echidna.yaml"
echo ""
