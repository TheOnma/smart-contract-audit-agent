# Smart Contract Audit Agent

> Reusable audit infrastructure: RAG-backed pattern matching, structured fuzzing, formal
> verification, and black-hat simulation. Point at any Solidity project with a CLAUDE.md.

---

## What This Agent Does

This repo is a methodology engine. Given a target Solidity project, it runs five parallel
workstreams to find Critical, High, and Medium severity findings:

1. **RAG pattern matching** — queries a corpus of prior audit findings for analogous bugs
2. **Structured fuzzing** — unit property tests + stateful invariant harness
3. **Black-hat simulation** — adversarial economic attack modeling
4. **Formal verification** — Halmos (bounded) + Certora rule generation
5. **Manual review methodology** — state invariant table technique + doc-code gap analysis

---

## How to Use

```bash
# Initialize for a target project
./init.sh /path/to/target-project

# Query RAG manually
python3 rag/query.py --pattern "callback before state write with ERC20 transfer"
python3 rag/query.py --category "fixed-rate-lending arithmetic"
python3 rag/query.py --fp "reentrancy during liquidation callback"

# Run fuzzing templates (after init.sh copies them to target)
cd /path/to/target-project
forge test --match-path "test/audit/*" --fuzz-runs 100000

# Run Halmos
halmos --contract MonotonicityCheck --function check_wExpMonotone --loop 3
```

---

## Methodology

### Phase 1 — Surface Triage

Before starting, read the target project's `CLAUDE.md`. Extract:
- What surfaces are already audited (do NOT re-investigate)
- What surfaces are explicitly excluded from Certora specs
- What surfaces the prior audits flagged as "needs more work"

These excluded/unverified surfaces are your starting point, not the whole codebase.

### Phase 2 — RAG-Backed Pattern Matching

For every function you review, fire two RAG queries:

**Pass 1 — Pattern query:** Extract the structural signature of the function
(auth check, math op, callback, state write, external call order) and ask:
> "Show me findings in protocols with this structural pattern."

**Pass 2 — Category query:** Ask by protocol type × vulnerability class:
> "Show me H/M findings in fixed-rate-lending protocols involving arithmetic rounding."

**Pass 3 — False positive check:** Before writing a PoC, ask:
> "Show me false positives that looked like this but weren't exploitable."

The false positive check is the most important pass. It prevents wasting days on dead ends.

### Phase 3 — State Invariant Table

For every function, fill out this table before looking for bugs:

```
Function: [name]

Pre-state (what must be true before entry):
  - [list conditions]

Storage mutations (what changes, in what direction):
  - [var]: [direction/amount]

Invariants this function must preserve:
  - [list what must remain true after]

What it assumes about other functions' work:
  - [dependencies on prior calls]

Timing dependencies:
  - [maturity, lock state, etc.]
```

State inconsistency bugs fall out automatically — when a mutation in row 2 has no
corresponding preservation check in row 3, that's a candidate finding.

### Phase 4 — Economic Feasibility Gate

Apply this gate to EVERY hypothesis before writing a PoC:

1. What is the attacker's capital requirement?
2. What is the expected gross profit?
3. What is the gas cost?
4. Who else (MEV bots, other wardens) competes to execute this first?
5. Is the net profit positive after gas and capital cost?

If net profit ≤ 0: the finding is at most a griefing vector. Downgrade severity.
This gate eliminates ~70% of false positives in lending protocol audits.

### Phase 5 — Black-Hat Attack Taxonomy

Run every open surface through all 9 attack categories:

| # | Category | Core question |
|---|---|---|
| 1 | **Drain** | Can I increase my claims without depositing? |
| 2 | **Bad debt amplification** | Can I force socialized losses while keeping profit? |
| 3 | **Oracle manipulation** | Can I flip health status mid-transaction? |
| 4 | **Price/tick gaming** | Can I exploit approximation errors to affect health checks? |
| 5 | **Fee extraction** | Can I claim more fees than I'm owed? |
| 6 | **Signature/replay** | Can I reuse a signature I received once? |
| 7 | **Permanent DoS** | Can I lock the protocol irreversibly (not just grieve)? |
| 8 | **MEV/sandwich** | Can I extract value from other users' transactions? |
| 9 | **Admin escalation** | Can I exploit absent timelocks or weak role controls? |

### Phase 6 — Fuzzing (Two Tiers)

**Tier 1 — Unit property tests (stateless, fast):**
Run with `--fuzz-runs 100000`. Target: pure math functions.
Template: `fuzzing/templates/UnitPropertyTests.t.sol`

Key properties to test:
- Monotonicity of any approximation function (Taylor, log, exp)
- `mulDivDown(x,y,d) ≤ mulDivUp(x,y,d)` always
- Round-trip math: `decode(encode(x)) == x` or within tolerance
- Tick/price mappings strictly monotone
- Scalar fields (lossFactor, accruedFee) never overflow their storage type

**Tier 2 — Stateful invariant tests (multi-actor harness):**
Template: `fuzzing/templates/InvariantHarness.t.sol`
Requires mock callback contracts: `fuzzing/templates/MockCallbackReceiver.sol`

Core invariants every lending protocol should have:
```
totalUnits >= sum(all_credits) + continuousFeeCredit
lossFactor is monotonically non-decreasing
lossFactor < type(uint128).max (never saturates)
consumed[maker][group] only increases
No new debt created after maturity
Contract ERC20 balance >= withdrawable + sum(collateral values)
```

Seed Echidna with corner states that random fuzzing never reaches:
- Scaling factor near type(uint128).max - 1
- Bad debt ≈ totalUnits - 1
- All collateral slots occupied (bitmap saturated)
- Position at exact maturity timestamp

### Phase 7 — Formal Verification (Falsifier Mode)

Formal verification is a **falsifier, not a finder**. You run it on a property you *think* holds.
If it finds a counterexample, that's your bug. Don't ask "find all bugs" — ask "prove or disprove
this specific property."

**Halmos** (bounded symbolic execution) — use for:
- Monotonicity of approximation functions over bounded input ranges
- Math overflow/underflow in `unchecked` blocks
- Property: "this value never exceeds X for all valid inputs"

Setup:
```bash
pip install halmos
halmos --contract YourCheck --function check_yourProperty --loop 3
# UNSAT = property holds (proven). SAT = counterexample found (your bug).
```

**Certora** — use for:
- Cross-function state consistency (e.g., multicall composability)
- Authorization invariants across all call paths
- Monotonicity properties that Halmos can't reach due to complexity

Write rules for whatever the existing Certora suite explicitly excludes.

**SMTChecker** (built into solc, zero setup) — use for:
- Arithmetic overflow/underflow in specific functions
- Division by zero detection
```bash
solc --model-checker-engine chc --model-checker-targets overflow src/YourFile.sol
```

### Phase 8 — Documentation-Code Gap Analysis

Feed both the docs/spec AND the code and ask:
> "List every place where the code does something the documentation doesn't mention,
> or where the code makes an assumption the documentation doesn't state explicitly."

This surfaces design-intent-implementation gaps that pure code reading misses.
Many Medium findings live here — the code is correct by its own logic, but the
deployment context or integration assumption is never written down.

### Phase 9 — Adversarial User Story

Force economic thinking, not just code defect thinking:
> "You are an attacker with unlimited capital and no morals.
> You want to drain maximum value from [Protocol] in a single transaction.
> Write your top 3 strategies as exact function call sequences with amounts."

Then: "For each strategy, what protocol state must be true for this to work? Can you
construct that state? What does it cost?"

---

## Project Context Injection

When this agent runs against a target project, it reads the project's `CLAUDE.md` and injects
it as context for every analysis. The project CLAUDE.md must contain:

- Protocol architecture and execution flow
- Prior audit findings (confirmed + eliminated false positives)
- Certora/formal verification exclusions
- Poisoned surfaces (already fixed, don't re-investigate)
- Open surfaces flagged for investigation

**If the target project has no CLAUDE.md**, run the `/x-ray` skill first to generate one.

---

## RAG Corpus Structure

```
rag/corpus/
├── morpho-blue/
│   ├── meta.json          {"name": "Morpho Blue", "type": "lending"}
│   ├── spearbit-2024.pdf
│   └── trail-of-bits-2024.pdf
├── notional-v2/
│   ├── meta.json          {"name": "Notional V2", "type": "fixed-rate-lending"}
│   └── report.md
└── ...
```

Each directory = one protocol. `meta.json` sets the protocol name and type tag used
in RAG queries. PDFs and markdown are both supported.

**Include false positives.** Add a `false-positives.md` in each protocol directory with
findings that looked real but weren't, plus the reasoning that ruled them out.
This is more valuable than the real findings for avoiding wasted PoC time.

---

## Finding Report Format

Every finding submitted from this agent must include:

```markdown
## [Severity] Title

**Protocol:** [name]
**File:** [path:line]
**Function:** [name]

### Summary
One sentence.

### Root Cause
Why is this exploitable? (not just what it does)

### Attack Path
Exact function call sequence with amounts and state prerequisites.

### Impact
What does the attacker gain? What do users lose?

### Economic Feasibility
- Capital required: [amount]
- Expected profit: [amount]
- Gas cost: [estimate]
- Net: [positive/negative]

### PoC
```solidity
// Foundry test demonstrating the exploit
```

### Analogous Prior Finding
[Protocol] [Severity] — [finding title] — [similarity score from RAG]

### Fix
One sentence.
```

A finding without a working PoC is a hypothesis, not a finding.

---

## Tool Reference

| Tool | Purpose | When to use |
|---|---|---|
| `rag/query.py --pattern` | Find analogous findings by code pattern | On every function review |
| `rag/query.py --fp` | Find similar false positives | Before writing PoC |
| `forge test --fuzz-runs 100000` | Unit property tests | After writing UnitPropertyTests.t.sol |
| `forge test --invariant` | Stateful invariant tests | After building InvariantHarness.t.sol |
| `halmos` | Bounded symbolic proof/disproof | For bounded-range properties (wExp, etc.) |
| `solc --model-checker-engine chc` | Static overflow detection | On math-heavy files |
| `echidna` | Corpus-seeded stateful fuzzing | When Foundry invariants miss corner states |
| `medusa` | Better coverage than Foundry invariant mode | For complex multi-actor state machines |
