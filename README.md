# Smart Contract Audit Agent

A reusable auditing system that combines RAG-backed pattern matching, property-based fuzzing, and formal verification templates. Point it at any Solidity project and it gives you the infrastructure a top warden uses — without rebuilding it from scratch each time.

---

## What it does

| Layer | Tool | What it answers |
|---|---|---|
| **RAG** | `rag/query.py` | "Has anyone found a bug like this before?" |
| **Fuzzing** | `test/audit/*.t.sol` | "Can I make this math break with specific numbers?" |
| **Formal** | `test/formal/` + `certora/` | "Can I prove this property holds for all inputs?" |
| **Black-hat** | `agents/blackhat.md` | "How would an attacker actually profit here?" |

---

## Prerequisites

```bash
# Foundry (for fuzzing)
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Halmos (for formal verification)
pip install halmos

# Echidna (for stateful fuzzing with corpus seeding)
brew install echidna-test

# Python RAG dependencies
pip install chromadb pdfplumber openai python-dotenv
```

---

## Setup for a new audit

### 1. Clone this repo

```bash
git clone https://github.com/TheOnma/smart-contract-audit-agent.git
cd smart-contract-audit-agent
```

### 2. Add your OpenAI key

Create `.env` in the repo root (it is gitignored — never committed):

```
OPENAI-KEY=sk-proj-your-key-here
```

### 3. Add your corpus documents

Drop audit reports (PDF, markdown, or txt) into subdirectories under `rag/corpus/`. Each subdirectory needs a `meta.json` identifying the protocol:

```
rag/corpus/
├── morpho-blue/
│   ├── meta.json          ← {"name": "Morpho Blue", "type": "lending"}
│   ├── spearbit-2024.pdf
│   └── trail-of-bits.pdf
├── notional-finance/
│   ├── meta.json          ← {"name": "Notional Finance", "type": "fixed-rate-lending"}
│   └── audit.pdf
└── my-new-protocol/
    ├── meta.json          ← {"name": "My Protocol", "type": "lending"}
    └── report.pdf
```

**Protocol type tags** (use these in `meta.json`):
- `lending` — variable-rate (Aave, Compound, Morpho Blue style)
- `fixed-rate-lending` — fixed-rate or zero-coupon (Notional, Pendle, Term Finance style)
- `amm` — AMM / DEX
- `yield` — yield aggregator / vault

You can also point `--corpus` at any external directory — it doesn't have to be inside this repo.

### 4. Build the RAG index

```bash
# From inside the smart-contract-audit-agent directory:
python3 rag/ingest.py --corpus rag/corpus

# Or point at a folder elsewhere on your machine:
python3 rag/ingest.py --corpus /path/to/your/Documents_for_rag

# Re-run this every time you add new documents. It rebuilds the index from scratch.
```

Output shows each file ingested and total chunk count. Typical run: ~30 seconds for 30 PDFs.

### 5. Wire the agent into your target project

```bash
./init.sh /path/to/your/solidity-project
```

This copies the fuzzing templates, Halmos checks, and Certora rule stubs into the target project's `test/audit/`, `test/formal/`, and `certora/audit_rules/` directories. It does not modify any existing tests.

---

## Querying the RAG

Run queries from inside the `smart-contract-audit-agent` directory. Three passes — use them in order:

### Pass 1 — Pattern match (start here)

When you're reading a function and something looks off:

```bash
python3 rag/query.py --pattern "mulDivDown rounding toward zero saturation"
python3 rag/query.py --pattern "callback before state write ERC20 transfer"
python3 rag/query.py --pattern "domain separator uses contract address not proxy"
```

Returns the most semantically similar findings from your corpus, ranked by similarity score.

### Pass 2 — Category sweep

When you want broad coverage of a surface area:

```bash
python3 rag/query.py --category "fixed-rate-lending arithmetic"
python3 rag/query.py --category "lending reentrancy" --severity high
python3 rag/query.py --category "amm oracle manipulation" --n 10
```

### Pass 3 — False positive check (always run before writing a PoC)

Before spending time on a PoC, check if this pattern was already investigated and ruled out:

```bash
python3 rag/query.py --fp "lossFactor update rounding toward zero"
python3 rag/query.py --fp "callback reentrancy during liquidation"
```

If similar patterns come back as false positives, read the reasoning before investing in a PoC.

### All high/medium findings

```bash
python3 rag/query.py --all-hm --n 20
python3 rag/query.py --all-hm --n 20 --full   # show full text, no truncation
```

### Options

| Flag | Description |
|---|---|
| `--n N` | Number of results (default: 5) |
| `--severity high\|medium\|low\|info` | Filter by severity |
| `--full` | Show complete finding text without truncation |
| `--db PATH` | ChromaDB path (default: `.rag/db`) |
| `--env PATH` | `.env` file path (default: repo root `.env`) |

---

## Fuzzing (inside your target project)

After running `init.sh`, three template files are in `test/audit/`:

### Unit property tests — fast, stateless

```bash
forge test --match-path "test/audit/UnitPropertyTests.t.sol" --fuzz-runs 100000 -vv
```

Open `test/audit/UnitPropertyTests.t.sol` and uncomment the tests relevant to your protocol's math. Pre-built property groups:
- **mulDiv rounding** — `mulDivDown ≤ mulDivUp`, never over/underestimates
- **Approximation monotonicity** — `wExp`, `tickToPrice`, any Taylor approximation
- **Scaling factor overflow** — loss factor / PV scaling never saturates storage type
- **Bitmap operations** — set/clear round-trips, isolation, idempotency
- **Fee interpolation** — stays within breakpoint bounds

A failing test gives you the exact counterexample inputs. That counterexample IS the bug.

### Invariant harness — stateful, multi-actor

```bash
forge test --match-path "test/audit/InvariantHarness.t.sol" \
           --invariant-runs 500 --invariant-depth 50 -vv
```

Open `test/audit/InvariantHarness.t.sol` and fill in the `[TODO]` sections:
1. Import your protocol contracts
2. Deploy them in `setUp()`
3. Fund the actors (Maker, Taker, Liquidator, Attacker)
4. Uncomment the invariant assertions

Core invariants already templated:
- `totalUnits >= sum(credits) + feeCredit`
- Scaling factor never hits `type(uint128).max`
- Scaling factor is monotonically non-decreasing
- `consumed` counter never decreases (anti-replay)
- No new debt after maturity

### Mock callbacks

`test/audit/MockCallbackReceiver.sol` implements three modes for `onBuy` / `onSell` / `onFlashLoan`:
- `HONEST` — transfers tokens back normally
- `REENTER` — attempts a configurable re-entrant call during the callback
- `GRIEF` — reverts immediately

Without this mock, the fuzzer never reaches the callback execution paths.

### Echidna (corpus-seeded fuzzing)

```bash
# From inside your target project:
echidna . --contract InvariantHarness --config echidna.yaml
```

Seed `setUp()` with dangerous corner states that random fuzzing won't naturally reach:
- Scaling factor at `type(uint128).max - 1`
- Bad debt ≈ total units
- Position timestamp exactly at maturity
- All collateral slots occupied (bitmap saturated)

---

## Formal verification

### Halmos — bounded symbolic proof

```bash
# From inside your target project:
halmos --contract MonotonicityCheck --function check_wExpMonotone --loop 3
```

- `UNSAT` = property is **proven** for all inputs in the bounded range
- `SAT` = counterexample found — Halmos gives you the exact input values

Open `test/formal/MonotonicityCheck.t.sol` and fill in your protocol's function names and input bounds. Pre-built checks:
- Approximation function monotonicity
- Scaling factor formula never overflows
- `mulDivDown` rounding direction

### Certora — cross-function invariants

Three rule stubs are in `certora/audit_rules/` after `init.sh`:
- `wexp_monotonicity.spec` — proves an approximation function is monotone
- `loss_factor_never_max.spec` — proves scaling factor can't saturate
- `multicall_no_auth_escalation.spec` — proves multicall can't escalate permissions

Uncomment the assertions and fill in your function signatures. Run with:

```bash
certoraRun src/YourContract.sol \
  --verify YourContract:certora/audit_rules/loss_factor_never_max.spec
```

### SMTChecker — zero setup, built into solc

```bash
solc --model-checker-engine chc --model-checker-targets overflow src/libraries/TickLib.sol
```

Catches arithmetic overflow in `unchecked` blocks statically. No test file needed.

---

## Adding more documents to the corpus

1. Create a new subdirectory in your corpus folder:
   ```
   rag/corpus/new-protocol/
   ├── meta.json    ← {"name": "Protocol Name", "type": "fixed-rate-lending"}
   └── report.pdf
   ```

2. Re-run ingest — it rebuilds the entire index from scratch:
   ```bash
   python3 rag/ingest.py --corpus rag/corpus
   ```

**What to add for best results:**
- Audit reports from protocols structurally similar to your target
- Top warden write-ups from Code4rena (narrative posts, not just the PDF — they include reasoning traces)
- A `false-positives.md` per protocol: patterns that looked exploitable but weren't, plus the reasoning that ruled them out. This is the most valuable thing you can add — it prevents wasting days on dead ends.

---

## Using the agent prompts

The `agents/` directory contains prompt files for four specialist sub-agents. Copy the relevant prompt into a Claude Code conversation and inject your target project's `CLAUDE.md` as context.

| Prompt | When to use |
|---|---|
| `agents/rag-reviewer.md` | Reviewing a specific function — fires all three RAG passes and flags pattern matches |
| `agents/blackhat.md` | After finding a candidate — builds the adversarial attack path with economic feasibility check |
| `agents/fuzz-runner.md` | Writing fuzz tests — generates targeted invariants for specific hypotheses |
| `agents/synthesis.md` | End of review — deduplicates findings, scores evidence, formats for submission |

The **economic feasibility gate** in `agents/blackhat.md` is the single most effective false-positive filter. Always run it before writing a PoC:
> Capital required? Expected profit? Gas cost? Net after gas = profit or loss?

If net ≤ 0 after gas, the finding is a griefing vector at best — downgrade severity.

---

## Full workflow example

```bash
# 1. Wire the agent into a new project
./init.sh /path/to/target-project

# 2. Query the RAG while reading the code
python3 rag/query.py --pattern "callback before state write with external call"
python3 rag/query.py --category "fixed-rate-lending arithmetic" --severity high

# 3. Run unit property tests on pure math functions
cd /path/to/target-project
forge test --match-path "test/audit/UnitPropertyTests.t.sol" --fuzz-runs 100000 -vv

# 4. If a test fails — you have a candidate finding
#    Run Pass 3 before writing the PoC:
cd /path/to/smart-contract-audit-agent
python3 rag/query.py --fp "the hypothesis description"

# 5. Run Halmos to formally prove or disprove a bounded property
cd /path/to/target-project
halmos --contract MonotonicityCheck --function check_yourProperty --loop 3

# 6. Fill in InvariantHarness.t.sol and run stateful fuzzing
forge test --match-path "test/audit/InvariantHarness.t.sol" \
           --invariant-runs 500 --invariant-depth 50 -vv
```

---

## Repository structure

```
smart-contract-audit-agent/
├── CLAUDE.md                        ← Full audit methodology (read this first)
├── README.md                        ← This file
├── init.sh                          ← Wire agent into a target project
├── requirements.txt                 ← Python dependencies
├── .env                             ← Your OpenAI key (gitignored, create manually)
│
├── rag/
│   ├── ingest.py                    ← Build the RAG index from audit reports
│   ├── query.py                     ← Query the RAG (3-pass strategy)
│   └── corpus/                      ← Put your audit report PDFs here
│       └── sources.md               ← Where to find the best corpus documents
│
├── fuzzing/
│   └── templates/
│       ├── UnitPropertyTests.t.sol  ← Stateless math property tests
│       ├── InvariantHarness.t.sol   ← Multi-actor stateful invariant harness
│       └── MockCallbackReceiver.sol ← onBuy/onSell/onFlashLoan mock
│
├── formal/
│   ├── halmos/
│   │   └── MonotonicityCheck.t.sol  ← Halmos bounded proofs
│   └── certora/rule_templates/
│       ├── wexp_monotonicity.spec
│       ├── loss_factor_never_max.spec
│       └── multicall_no_auth_escalation.spec
│
└── agents/
    ├── rag-reviewer.md              ← Prompt: RAG-backed function review
    ├── blackhat.md                  ← Prompt: adversarial attack modeling
    ├── fuzz-runner.md               ← Prompt: write targeted fuzz tests
    └── synthesis.md                 ← Prompt: deduplicate + rank findings
```

---

## Tips

**The false-positive RAG entries are worth more than the real findings.** When you add a new protocol's corpus, also add a `false-positives.md` documenting patterns that looked exploitable but weren't. This is what separates a junior who files 20 false positives per real finding from a senior who files 1:1.

**Run Pass 3 before every PoC.** The query takes 2 seconds. A PoC takes hours. The false-positive check has saved more time than any other single habit.

**`MAX_CHUNK_CHARS` in `ingest.py` is tunable.** Default is 4000 characters. If query results feel too narrow (missing context), raise it to 8000. If OpenAI returns token limit errors on a new document, lower it to 2000.

**`init.sh` is idempotent.** Running it twice on the same project skips files that already exist. Safe to re-run after updating templates.
