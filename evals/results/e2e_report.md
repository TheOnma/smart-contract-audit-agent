# End-to-End Detection Benchmark (simulated review)

**20 vulnerable code surfaces** (real confirmed C4/Cantina findings, input = the code an auditor sees, no vulnerability language) + **5 clean surfaces**. Reviewer = deterministic implementation of `agents/rag-reviewer.md` (Pass 1 pattern match, Pass 2 category sweep, Pass 3 FP check). Candidate = finding with similarity ≥ threshold.

| Metric | t=0.4 | t=0.5 | t=0.6 |
|---|---|---|---|
| Detection rate (recall on bugs) | 0.95 | 0.95 | 0.75 |
| Top-candidate rate (GT ranked #1) | 0.474 | 0.474 | 0.533 |
| Mean candidates per review | 7 | 4.95 | 3 |
| False-positive rate (clean) | 1 | 0.6 | 0.4 |
| False-positive rate after FP gate | 0 | 0 | 0 |

At the headline threshold **t=0.5** (the reviewer prompt's 'similarity < 0.5 → don't report' rule): detected 0.95 (19/20), of which pass-1-only 19, pass-2-only 0, both 0; 10 reviews had no category signal in the code (Pass 2 skipped); 8 had a similar false-positive entry (reviewer double-checks).

## Per-case (vulnerable)

| Case | Severity | Detected | GT rank | Pass | FP entry | Latency (s) |
|---|---|---|---|---|---|---|
| bakerfi-first-depositor-inflation | high | ✅ | 1 | P1 | — | 4.34 |
| bakerfi-h01-oracle-decimals | high | ✅ | 1 | P1 | ⚠️ | 3.27 |
| bakerfi-m06-oracle-bounds | medium | ✅ | 3 | P1 | ⚠️ | 3.14 |
| renzo-queued-withdrawal-tvl-deflation | high | ✅ | 2 | P1 | — | 2.36 |
| renzo-h01-contract-recipient-lock | high | ✅ | 2 | P1 | ⚠️ | 4.81 |
| renzo-h03-eth-withdraw-fail | high | ✅ | 2 | P1 | — | 3.43 |
| renzo-withdrawal-mev-slippage | high | ✅ | 3 | P1 | ⚠️ | 3.83 |
| renzo-dos-buffer-filled | high | ✅ | 1 | P1 | — | 2.6 |
| renzo-h08-withdraw-queue-tvl | high | ✅ | 2 | P1 | — | 2.35 |
| renzo-m03-stale-heartbeat | medium | ✅ | 3 | P1 | ⚠️ | 3.46 |
| ethena-cooldown-not-applied | medium | ✅ | 1 | P1 | — | 3.48 |
| ethena-m01-full-restricted-approval | medium | ✅ | 1 | P1 | ⚠️ | 3.32 |
| ethena-susde-m01-blacklist-burn | medium | ❌ | — | — | ⚠️ | 3.95 |
| ondo-h01-cash-redemption-loss | high | ✅ | 1 | P1 | — | 2.57 |
| ondo-m04-kyc-replay | medium | ✅ | 2 | P1 | — | 2.52 |
| tapioca-nft-theft-approval | high | ✅ | 5 | P1 | — | 2.28 |
| tapioca-twaml-burn-grief | medium | ✅ | 1 | P1 | — | 5.11 |
| ovault-hub-eid-transfer-fail | medium | ✅ | 3 | P1 | ⚠️ | 2.9 |
| ovault-h1-refund-loss | high | ✅ | 1 | P1 | — | 3.24 |
| ovault-m2-slippage-locked | medium | ✅ | 1 | P1 | — | 2.73 |

## Clean surfaces (false-positive check)

| Case | Candidate surfaced (t=0.5) | FP gate |
|---|---|---|
| clean-multisig | ⚠️ FP (1 candidates) | ✅ caught |
| clean-timelock | ✅ none | ⚠️ flagged (no candidate) |
| clean-merkle | ✅ none | — |
| clean-erc20 | ⚠️ FP (5 candidates) | ✅ caught |
| clean-oracle-guarded | ⚠️ FP (5 candidates) | ✅ caught |

FP gate: Pass 3 matches the clean surface against triaged false-positives corpus entries; a clean review counts as a *shipped* false positive only if a candidate surfaced and the gate did NOT fire (gate caught 3/3 of the pre-gate FPs at t=0.5).


### Misses at t=0.4

- ethena-susde-m01-blacklist-burn

### Misses at t=0.5

- ethena-susde-m01-blacklist-burn

### Misses at t=0.6

- bakerfi-m06-oracle-bounds
- renzo-h08-withdraw-queue-tvl
- ethena-susde-m01-blacklist-burn
- tapioca-twaml-burn-grief
- ovault-hub-eid-transfer-fail

Cost: text-embedding-3-small (~$0.02/1M tokens), 3 embedding queries per review (Pass 1 + Pass 2 + Pass 3). Est. mean cost 4.99e-06 USD/review. Mean latency 3.28s/review.
