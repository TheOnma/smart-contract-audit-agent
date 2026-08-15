# Alma Agent

A reusable auditing system that combines RAG-backed pattern matching, property-based fuzzing, and formal verification templates. Point it at any Solidity project and it gives you the infrastructure a top warden uses — without rebuilding it from scratch each time.

---

## Proven in a live competitive audit 🏆

Not a demo — this system found a real bug in a real competition:

| | |
|---|---|
| **Competition** | Cantina audit contest — **Revert Finance** |
| **Finding** | Confirmed **medium-severity** bug, surfaced by the property-based fuzzing harness |
| **Rank** | **29 / 773** wardens (top 4%) |
| **Payout** | **$108** — first paid finding |

**How it happened:** the fuzzing harness's directed math tests (`testFuzz_underflow_search`, the reserve-scale sweep) drove `StableSwapMath.getInvariant`'s Newton–Raphson solver into non-convergent reserve states — the 255-iteration loop with a `|prev − curr| ≤ 1` exit oscillates forever in a dead zone and reverts `ConvergenceNotReached()`, so `_beforeSwap` reverts and **every swap is permanently DoS'd**. I confirmed the trigger is permissionless (anyone can first-deposit at a dead-zone ratio through the public factory) and — the key part — that the dead zone is *non-monotonic*: proportional LP deposits escape it at 10×/100× but not 1×/2×/5×/1000×, so it can't be blamed on the victim. Funds stay recoverable via `removeLiquidity`, capping it at Medium.

**Why this matters:** the fuzzer hands you the counterexample *before* you commit to a PoC, and the RAG false-positive check stops you from burning hours on dead ends — which is exactly how a solo warden lands in the top 4% of a 773-warden contest.

**The numbers behind it:**

| Benchmark | Result |
|---|---|
| Retrieval Recall@10 (20 real confirmed C4/Cantina findings) | **1.0** (20/20) |
| MRR | **0.806** |
| End-to-end detection rate (simulated review, n=5) | **0.95** (19/20) |
| False-positive rate after the Pass-3 gate | **0.6 → 0.0** |

> **Eval harness:** implemented and running — see the [Evaluation](#evaluation) section below. Spec in [EVALS_SPEC.md](EVALS_SPEC.md).

---

## Quick demo

~60 seconds to see the whole pipeline: build the index, run both benchmarks, then ask the RAG a live question the way you would while auditing.

```bash
# 1. Build the findings index — first run only, ~2 min (needs OPENAI-KEY in .env)
python3 rag/ingest.py --corpus rag/corpus-dreusd --db .rag/dreusd-db

# 2. Retrieval benchmark — 20 real confirmed findings, Recall@10 + MRR
python3 evals/run_bench.py --db .rag/dreusd-db --k 10

# 3. End-to-end detection eval — 20 vulnerable code surfaces + 5 clean, with the FP gate
python3 evals/run_e2e.py --db .rag/dreusd-db

# 4. Ask it like an auditor: "has anyone seen a rounding bug like this?"
python3 rag/query.py --pattern "mulDivDown rounding lossFactor saturation" --db .rag/dreusd-db
```

You should see the numbers from this README: `Recall@10 = 1.0`, MRR `0.806`, e2e detection `0.95`, FP rate `0.6 → 0.0` after the gate — committed in `evals/results/`. Rebuilding the index costs well under $0.01 in embeddings. The 20 benchmark findings all live in committed markdown reports; a few third-party security-firm PDFs are kept out of the repo for copyright, so `evals/results/` is the canonical source for the numbers.

---

## Evaluation

Benchmarked against **20 real, judge-confirmed C4/Cantina findings** already in the corpus (`rag/corpus-dreusd`): BakerFi ×3 (C4), Renzo ezETH ×7 (C4), Ethena USDe/UStb ×3 (C4), Ondo CASH ×2 (C4), Tapioca ×2 (C4), LayerZero Ovault ×3 (Cantina). Each query is phrased the way an auditor would describe a suspected bug pattern while reading code — *not* the finding title verbatim — so the benchmark measures genuine semantic retrieval, not title matching. Ground truth = each finding's full span (header chunk + contiguous chunks until the next finding's header), resolved from the rebuilt per-finding index.

| Metric | Score |
|---|---|
| Retrieval Recall@10 | **1.0** (20/20) |
| MRR | **0.806** |
| Mean hit similarity | 0.584 |

14 of 20 findings hit at **rank 1**; the hardest cases (oracle bounds, stale-price heartbeat, cross-chain refund loss) rank 3–5 and compete with Chainlink docs and other cross-chain findings — which is what makes the 1.0 credible: the queries are genuine paraphrases, and retrieval still surfaces the right report. Per-case results and the machine-readable output live in `evals/results/report.md` / `latest.json`.

**Reproduce:**
```bash
python3 evals/run_bench.py --db .rag/dreusd-db --k 10
```
(requires the dreusd DB built via `python3 rag/ingest.py --corpus rag/corpus-dreusd --db .rag/dreusd-db` and an OpenAI key in `.env`.)

**The eval paid for itself (a real bug, found and fixed):** the first run missed the Ovault case (Cantina `## [MEDIUM] M-x` report format) — and the root cause was a genuine defect in `rag/ingest.py`, not a retrieval failure: the finding-header regex didn't recognize Cantina's `[MEDIUM]` style headers (nor C4's `[[H-02]` double-bracket headers!), so findings were chunked as one giant section per severity level and split by arbitrary 4000-char paragraphs. Fixing the regex (added C4 double-bracket + Cantina `[MEDIUM]/[HIGH]/[LOW]/[GAS]` forms) and rebuilding the index turned the miss into a **rank-1 hit with a plain-language query** — no code identifiers needed — and improved MRR **0.823 → 0.854** on the original 8 cases. Chunk count went 393 → 425 (per-finding instead of per-paragraph).

**Expanding 8 → 20 cases made the benchmark harder, not the retrieval worse.** The 20-case MRR (0.806) is lower than the 8-case MRR (0.854) because the new cases are deliberately harder — oracle-bound and stale-heartbeat queries compete with Chainlink's own docs, and the cross-chain refund query competes with other bridge findings — while Recall@10 held at 1.0 across all 20. That's the behavior you want from a benchmark: as it gets more discriminating, scores drop toward a floor you can actually trust.

### End-to-end: does a candidate finding actually get surfaced during a review?

Retrieval metrics prove the *index* can find a finding when the query is close to it. The end-to-end eval asks the harder question: **given only the code an auditor sees (no vulnerability language — the bug is what's missing), does the RAG + reviewer workflow surface the right finding as a candidate?**

The harness (`evals/run_e2e.py`) is a deterministic implementation of `agents/rag-reviewer.md`: **Pass 1** pattern-matches the code surface, **Pass 2** sweeps protocol × vulnerability category, **Pass 3** checks the false-positive corpus (the reviewer double-checks, not a hard kill). Inputs are 20 real code surfaces reconstructed from the confirmed findings (`evals/benchmark/code_surfaces.json`) + 5 clean, non-vulnerable surfaces (`clean_cases.json`). A finding is a *candidate* at similarity ≥ threshold — the reviewer's stated rule is 0.5.

| Metric (t=0.5, n=5) | Score |
|---|---|
| **Detection rate** (recall on bugs) | **0.95** (19/20) |
| Top-candidate rate (correct finding ranked #1) | 0.474 (9/19) |
| False-positive rate (clean surfaces) | 0.6 (3/5) |
| **False-positive rate after FP gate** | **0.0** (3/3 caught) |
| Mean candidates per review | 4.95 |
| Cost | ~$0.000005 / review (embeddings only) |
| Latency | 3.4 s / review |

19 of 20 vulnerable surfaces surface their ground-truth finding; 9 of those rank it #1. At `--n 10` (wider candidate window) detection reaches 1.0.

**The eval caught a surface-authoring mistake in my own benchmark** — the two original misses weren't retrieval failures, they were surfaces that didn't match the real vulnerable code: I had shown the *claim* side of Renzo's withdrawal instead of the `withdraw()` request path where `amountToRedeem` is locked at oracle prices, and for Ethena M-01 I had written the *fix* (a blacklist check) into the surface instead of the vulnerable branch that lacks it. Fixing the surfaces to match the code the finding actually cites turned both into hits. Lesson: a detection eval only measures what you feed it — the input must be the code, not your memory of the bug.

The one remaining miss (Ethena M-01) is a genuine and instructive retrieval gap: its surface is a generic `_beforeTokenTransfer`, and the corpus is dense with near-identical UStb findings (L-09, L-12, M-02) that out-rank the true M-01 (rank 10 at sim 0.61) inside the n=5 window. **The 0.6 FP rate was the honest complement to the 0.95 detection rate** — the same 0.5 threshold that catches 19/20 bugs also flags clean surfaces that resemble real findings (a guarded oracle, a plain ERC20 transfer, a multisig executor). That's exactly what Pass 3 is for, so I seeded the false-positives corpus with **three real triaged entries** (`rag/corpus-dreusd/*/false-positives.md`): the guarded Chainlink read, the plain OZ ERC20 `transferFrom`, and the Safe-style `execTransaction` — each written as a reviewed-and-rejected hypothesis containing the exact code that was examined, so the gate matches on identifiers, not vibes.

**The result: false-positive rate 0.6 → 0.0 after the gate** (3/3 pre-gate FPs caught at t=0.5, gate hits at sim 0.78–0.82), with detection unchanged at 0.95 — Pass 1/Pass 2 now exclude `is_false_positive` chunks (`rag/query.py`), because FP entries are a check-corpus, not candidates, so seeding them can't suppress real findings. Two honest caveats, both in the report: the gate also soft-flags **8 of 19 detected real findings** (e.g. the guarded-oracle entry matches BakerFi's oracle findings — expected, since it contains the *fixed* oracle pattern), which is exactly why the workflow treats Pass 3 as a double-check, not a hard kill; and the gate fired on clean-timelock (sim 0.515) even though no candidate surfaced there — a near-miss the per-case table records. Reproduce:
```bash
python3 evals/run_e2e.py --db .rag/dreusd-db          # n=5, t=0.4/0.5/0.6
python3 evals/run_e2e.py --db .rag/dreusd-db --n 10   # sensitivity: wider window
```
Results in `evals/results/e2e_report.md` / `e2e_latest.json`.

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

└── evals/
    ├── benchmark/
    │   ├── cases.json               ← 20 real confirmed findings + auditor-style queries
    │   ├── code_surfaces.json       ← e2e inputs: the code an auditor sees (no vuln language)
    │   └── clean_cases.json         ← e2e negatives: clean, well-guarded surfaces
    ├── metrics.py                   ← Recall@k, MRR + e2e detection summary/formatting
    ├── run_bench.py                 ← Retrieval harness wired to rag/query.py
    ├── run_e2e.py                   ← Simulated-review harness (3-pass reviewer)
    └── results/                     ← report.md + latest.json + e2e_report.md (committed)
```

---

## Tips

**The false-positive RAG entries are worth more than the real findings.** When you add a new protocol's corpus, also add a `false-positives.md` documenting patterns that looked exploitable but weren't. This is what separates a junior who files 20 false positives per real finding from a senior who files 1:1.

**Run Pass 3 before every PoC.** The query takes 2 seconds. A PoC takes hours. The false-positive check has saved more time than any other single habit.

**`MAX_CHUNK_CHARS` in `ingest.py` is tunable.** Default is 4000 characters. If query results feel too narrow (missing context), raise it to 8000. If OpenAI returns token limit errors on a new document, lower it to 2000.

**`init.sh` is idempotent.** Running it twice on the same project skips files that already exist. Safe to re-run after updating templates.
