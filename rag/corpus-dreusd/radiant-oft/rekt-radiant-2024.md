# Radiant Capital — Fork — REKT (Jan 3 2024)

Source: rekt.news. Loss: 1,900 ETH (~$4.5M) on Arbitrum.

> dreUSD relevance: this is the canonical **empty-market / first-deposit rounding** post-mortem. Radiant is a LayerZero-OFT protocol but the hack itself is the Aave-V2-fork zero-`totalSupply` rounding bug. Maps directly to the dreUSDs first-depositor / zero-share class (and to OVault M-1 inflation). The lesson — "never let a share/market sit empty; seed an initial deposit" — is the mitigation to check for in dreUSDs.

## What happened
- Radiant is a fork of Aave V2 on Arbitrum + BSC. The hack hit the Arbitrum deployment's **newly-launched native USDC market**.
- The bug affects **recently-launched (and therefore empty) markets**. A brief window after launch lets an attacker use a **flash loan to manipulate the value of collateral**, via the combination of a **rounding error and a `totalSupply` of 0**.
- The attacker deployed their attack contract **six seconds after the new market was activated** — fully prepared in advance, waiting for the market-add proposal (passed Dec 25) to be enacted.

## Root cause / known bug
- This is a known Aave-V2-fork issue. The original Aave protocol **mitigated it by including an initial deposit on new-market creation**, ensuring markets are never empty (never `totalSupply == 0`).
- Forks that copy the code without the operational mitigation re-introduce the vuln.

## Lessons
- Empty markets / vaults with `totalSupply == 0` + rounding = first-depositor / inflation manipulation.
- Mitigation is a seeded initial deposit (and/or virtual shares / decimals offset / round-up on share mint).
- Forked code carries patched-elsewhere bugs; fewer eyes than the high-TVL original. Timely updates matter.
- Despite four audits (OpenZeppelin, BlockSec, Peckshield, Zokyo), the empty-market path was exploited.

Addresses: attacker `0x826d5f4d8084980366f975e10db6c4cf1f9dde6d`; attack contract `0x39519c027b503f40867548fb0c890b11728faa8f`.
