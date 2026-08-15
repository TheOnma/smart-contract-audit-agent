# dreUSD Audit Corpus — Sources

> RAG corpus for the **dreUSD** protocol audit (Sherlock contest `2026-04-dre-labs-audits`).
> Built to mirror dreUSD's risk classes, not generic lending. Tag vocabulary used in
> `meta.json` `type` (so `query.py --category "<type> <vuln-class>"` resolves):
>
> `stablecoin` · `erc4626-vault` · `staking-rewards` · `oracle` · `bridge-oft` · `withdrawal-queue`
>
> Ingested into a SEPARATE db (`.rag/dreusd-db`) so the lending corpus in `.rag/db` is preserved.
>
> ```bash
> ~/anaconda3/bin/python rag/ingest.py --corpus rag/corpus-dreusd --db .rag/dreusd-db --project dreusd
> ~/anaconda3/bin/python rag/query.py  --db .rag/dreusd-db --category "erc4626-vault donation rounding"
> ~/anaconda3/bin/python rag/query.py  --db .rag/dreusd-db --pattern "OFT shared decimals dust truncation _removeDust"
> ```

---

## dreUSD surface → corpus bucket map

| dreUSD surface | Historical bug class | Bucket folder(s) |
|---|---|---|
| `dreUSDs` ERC4626 share price / first-depositor / `_virtualBalance` | 4626 inflation & donation | `morpho-metamorpho`, `openzeppelin-erc4626`, `yearn-v3`, `tapioca` |
| `dreRewardsDistributor` vest schedule / "share price only up" | reward-vesting rounding | `sablier-v2`, `synthetix-stakingrewards`, `ethena-susde` |
| `dreUSDOracle` staleness / L2 sequencer / decimals | L2 oracle post-mortems | `oracle-findings`, `chainlink-l2-oracle` |
| Fiat-mint path / custodian sig / replay / sanctions allowlist | custodial mint-without-backing | `ethena-usde`, `ondo-rwa-stablecoin`, `mountain-usdm`, `crvusd` |
| `fillWithdrawal` / `fillExpressWithdrawals` batch revert | withdrawal-queue batch DoS | `lido-withdrawal-queue` |
| `ovault/*` OFT, OFTAdapter lockbox, composer overrides, `_credit` bypass | LZ OFT V2 footguns | `layerzero-v2`, `stargate-v2`, `ovault-composer`, `radiant-oft` |

---

## ✅ Downloaded (in-repo, ingested — 390 chunks in `.rag/dreusd-db`)

| Folder | File(s) | Source |
|---|---|---|
| morpho-metamorpho | oz-metamorpho-v1.1, cantina-metamorpho-v1.1, cantina-metamorpho-diff, cantina-metamorpho (4 pdf) | OpenZeppelin + Cantina — MetaMorpho |
| tapioca | c4-tapioca-report.md | Code4rena — Tapioca (4626 + LayerZero OFT) |
| yearn-v3 | mixbytes-yearn-v3.pdf | MixBytes — Yearn Vaults V3 (ERC4626) |
| openzeppelin-erc4626 | oz-inflation-defense.md | OZ blog — Novel Defense Against ERC4626 Inflation |
| ethena-usde | c4-ethena-report.md | Code4rena — Ethena USDe (custodial mint/stake) |
| ethena-susde | quantstamp-ethena-susde, spearbit-ethena-susde-oct (pdf) + c4-ethena-2024-report.md | Quantstamp + Spearbit + C4 — Ethena (StakedUSDe/cooldown) |
| ondo-rwa-stablecoin | c4-ondo-rwa-report.md | Code4rena — Ondo (RWA stablecoin + KYC allowlist) |
| mountain-usdm | oz-mountain-usdm, oz-mountain-wusdm-erc4626 (2 pdf) | OpenZeppelin — Mountain USDM + wUSDM (ERC4626 wrapper) |
| crvusd | mixbytes-crvusd.pdf | MixBytes — crvUSD (Curve stablecoin) |
| oracle-findings | c4-renzo-oracle-report.md, c4-bakerfi-vault-oracle-report.md | Code4rena — Renzo + BakerFi (Chainlink staleness/sequencer) |
| chainlink-l2-oracle | chainlink-l2-sequencer-feeds.md, chainlink-selecting-data-feeds.md | Chainlink docs (sequencer grace, minAnswer/maxAnswer, staleness) |
| sablier-v2 | cantina-sablier-lockup-v2.pdf | Cantina — Sablier Lockup v2 (vesting math) |
| lido-withdrawal-queue | certora-lido-v2, hexens-lido-v2, chainsecurity-lido-v2 (3 pdf) | Certora + Hexens + ChainSecurity — Lido V2 (WithdrawalQueue) |
| layerzero-v2 | zellic-lz-oapp-oft, zellic-lz-oapp-oft-2, zellic-lz-endpoint-v2 (3 pdf) | Zellic — LayerZero OApp/OFT + Endpoint V2 |
| stargate-v2 | ottersec-stargate-v2.pdf | OtterSec — Stargate V2 (production OFT) |

---

## ⬜ Still missing — links only (auto-fetch blocked; copy the page/PDF in by hand)

These three folders are empty (no public raw file). Paste the report text into a `.md` in the folder, then re-run ingest.

- **`ovault-composer/`** — LayerZero **OVault / VaultComposerSync** audit (THE base `dreOVaultComposer` overrides; highest fresh-bug odds). Cantina-hosted, login-gated:
  https://cantina.xyz/portfolio/e4d93441-0fe3-4b64-bf98-fa31ecef4fb5 · docs: https://docs.layerzero.network/v2/developers/evm/ovault/overview
- **`radiant-oft/`** — Radiant Capital (LayerZero OFT) post-mortem (rekt.news blocks bots, returns 500 to curl):
  https://rekt.news/radiant-rekt2 · earlier: https://rekt.news/radiant-rekt
- **`synthetix-stakingrewards/`** — Synthetix `StakingRewards` reward-rate math / known issues (covered indirectly by Sablier + Ethena, but the canonical source):
  https://github.com/Synthetixio/synthetix (audits in repo) · https://docs.synthetix.io

### Optional extras (buckets already well-covered)
- crvUSD **ChainSecurity** (SPA-routed, not a raw PDF): https://www.chainsecurity.com/security-audit/curve-stablecoin
- More LayerZero V2 (Trail of Bits / Paladin): github.com/Zellic/publications + firm sites
- Solodit tag exports (`ERC-4626`, `Oracle`, `DoS`) → drop as `.md` into the matching folder

---

## Aggregators (bulk-pull more findings)
- **Solodit** — solodit.cyfrin.io (filter by tag; export finding text per bucket)
- **Code4rena** — github.com/code-423n4 (`<contest>-findings/report.md`) · code4rena.com/reports
- **Sherlock** — github.com/sherlock-audit · audits.sherlock.xyz/contests
- **Spearbit / Cantina** — github.com/spearbit/portfolio · cantina.xyz/portfolio
- **Zellic** — github.com/Zellic/publications
- **Rekt** — rekt.news (post-mortems)
- **DeFiHackLabs** — github.com/SunWeb3Sec/DeFiHackLabs (Foundry PoCs as fuzz corner-states)

---

## Per-folder `false-positives.md`
Each folder has a `false-positives.md` stub. Fill it as you triage: a pattern that looked like a dreUSD
bug here but wasn't, plus the reasoning. Per the agent design this is the highest-value file — the `--fp`
pass queries these to kill dead-end PoCs before you write them.
