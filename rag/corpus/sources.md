# Corpus Sources

Add audit reports here as: `corpus/<protocol-name>/report.pdf` or `report.md`
Each protocol directory needs a `meta.json` with name and type.

## meta.json format

```json
{
  "name": "Protocol Name",
  "type": "fixed-rate-lending"
}
```

## Protocol type tags (use these consistently)

- `lending` — variable-rate lending (Aave, Compound style)
- `fixed-rate-lending` — fixed-rate or zero-coupon (Notional, Term Finance, Morpho Midnight)
- `amm` — AMM/DEX
- `yield` — yield aggregator / vault
- `derivatives` — options, perps, structured products
- `bridge` — cross-chain
- `governance` — DAO / voting

---

## Priority Tier 1 — Structural analogues to Morpho Midnight

### morpho-blue/
- Spearbit audit (2024): https://github.com/morpho-org/morpho-blue/tree/main/audits
- Trail of Bits audit: same repo
- OpenZeppelin audit: same repo
```
meta.json: {"name": "Morpho Blue", "type": "lending"}
```

### notional-v2/
- Code4rena contest: https://code4rena.com/audits/2021-08-notional-finance
- Notional V3 contest: https://code4rena.com/audits/2023-03-notional-finance-v3
```
meta.json: {"name": "Notional V2", "type": "fixed-rate-lending"}
```

### term-finance/
- Sherlock contest: https://audits.sherlock.xyz/contests/term-finance
- C4 contest: https://code4rena.com/audits/term-finance
```
meta.json: {"name": "Term Finance", "type": "fixed-rate-lending"}
```

### pendle-finance/
- Multiple Sherlock + C4 contests: search "Pendle" on both platforms
```
meta.json: {"name": "Pendle Finance", "type": "fixed-rate-lending"}
```

### euler-finance/
- Trail of Bits (2022): https://github.com/euler-finance/audits
- OpenZeppelin: same repo
- Focus on: oracle manipulation and liquidation bugs
```
meta.json: {"name": "Euler Finance", "type": "lending"}
```

---

## Priority Tier 2 — Fixed-rate adjacent

### element-finance/
- PeckShield, Trail of Bits: https://github.com/element-fi/elf-contracts/tree/main/audits
```
meta.json: {"name": "Element Finance", "type": "fixed-rate-lending"}
```

### sense-finance/
- Spearbit: https://github.com/sense-finance/sense-v1/tree/dev/audits
```
meta.json: {"name": "Sense Finance", "type": "fixed-rate-lending"}
```

---

## Include false positives

For each protocol, add a `false-positives.md` with findings that looked real but weren't,
plus the reasoning that ruled them out. Structure:

```markdown
## [Pattern that looked exploitable]

**Why it seemed real:** [description]
**Why it's actually safe:** [the invariant or constraint that makes it safe]
**How to tell the difference:** [specific check to distinguish real vs false]
```

The false positive file is MORE valuable than the real findings for efficient future audits.
Name it exactly `false-positives.md` so the ingest script tags it correctly.

---

## Top Warden Write-ups (most valuable source)

These contain the reasoning trace, not just the finding. Download the submission text
(not the PDF report) from Code4rena profiles for:

- Trust (trust1995p)
- Getber (Getber)  
- 0x52 (0x52)
- \_\_141345\_\_ (\_\_141345\_\_)
- rvierdiiev (rvierdiiev)
- bin2chen (bin2chen)

Search their profiles for contests involving lending, fixed-rate, or tick-based pricing.
Save each write-up as `<protocol-name>/<warden>-writeup.md`.
