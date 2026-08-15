# LayerZero Ovault — Security Review (Cantina Managed, July 29 2025)

Reviewers: Gerard Persoon (Lead), Sujith Somraaj. Review of `devtools` @ commit `5167acfb` (Jul 2–3 2025).
Total: 20 issues — 1 High, 5 Medium, 4 Low, 1 Gas, 9 Info (all fixed).

> dreUSD relevance: `dreOVaultComposer` overrides `_refund`, `_sendLocal`, `_depositAndSend`, `_redeemAndSend` over THIS exact `OVaultComposer`/`VaultComposerSync` base. Every finding below is a checklist item for those overrides. The vault inflation finding (M-1) compounds with the dreUSDs `_virtualBalance` first-depositor concern.

---

## [HIGH] H-1 Permanent loss of user funds due to logical error in refunds
Context: `OVaultComposer.sol#L70, L83, L151`

The composer decodes `sendParam` from the source-chain compose message. On a **valid decode** it sets `sendParam.amountLD = 0` (the raw SendParam is forwarded to the target OFT, amount zeroed). That zeroed `sendParam` (not the separate `refundSendParam`) is then what gets stored in `failedMessages` and later used by `refund()`:

```solidity
try this.decodeSendParam(sendParamEncoded) returns (SendParam memory sendParamDecoded) {
    sendParam = sendParamDecoded;
    sendParam.amountLD = 0; // <<< zeroed
} catch { ... }
// later:
function refund(bytes32 _guid, bytes calldata _extraOptions) external payable nonReentrant {
    FailedMessage memory failedMessage = failedMessages[_guid];
    SendParam memory refundSendParam = failedMessage.sendParam; // <-- amountLD is zero (BUG)
```

Two failure modes:
- **Case 1 (invalid peer):** dest shareOFT/assetOFT lacks a peer for the final settlement chain → should refund to source. But refund sends `amountLD = 0`: if `minAmountLD > 0` → permanently DoSed with `SlippageExceeded`; if `minAmountLD == 0` → refunds **zero tokens** (funds locked on hub).
- **Case 2 (undecodable composeMsg):** stored sendParam is zero, `NoPeer()` on refund attempt.

Root cause: `refund()` uses `failedMessage.sendParam` instead of `failedMessage.refundSendParam`.
Fix:
```diff
- SendParam memory refundSendParam = failedMessage.sendParam;
+ SendParam memory refundSendParam = failedMessage.refundSendParam;
```
Also flagged: inadequate tests for the `refund()` flow. Fixed in `607200e7`.

---

## [MEDIUM] M-1 Inflation attack is more profitable due to overridden vault functions
Context: `OVault.sol#L10, OVaultUpgradeable.sol#L11`

`OVault`/`OVaultUpgradeable` inherit OZ ERC4626 and **override `_convertToShares()` and `_convertToAssets()`**, discarding the base's `_decimalsOffset()` and `+1` rounding protections → inflation attack becomes profitable on the **first transaction**, same-chain depositors affected (cross-chain is slippage-protected; can be used to DoS cross-chain deposits into the retry path). Impact HIGH, likelihood LOW.

PoC sequence:
1. Attacker deposits 1 wei assets → 1 wei shares.
2. Attacker donates 10,000 tokens to the vault.
3. Victim deposits 10,000 tokens → receives **0 shares** (overridden rounds down; OZ would round up).
4. Attacker redeems 1 wei share for entire vault (20,000 tokens + 1 wei).

Recommendation: round up to avoid minting zero shares (or override `deposit` to revert on zero shares); reinstate `_decimalCorrection()` / decimals offset. Fixed `fae8a363`.

> dreUSD: dreUSDs uses `_virtualBalance` (not balanceOf) and offset=0 — same "victim mints 0 shares on rounding-down" class. Confirm dreUSDs deposit reverts on zero-share mint AND that the `vestedAmount()` term in `totalAssets()` isn't a second donation vector (donate via the rewards path).

## [MEDIUM] M-2 Funds locked if slippage params cannot be satisfied
Context: `OVaultComposer.sol#L177`

On deposit, if output < expected the tx is marked failed and retried via `retryWithSwap()`. If the user supplied a wrong value or the price never reaches the level, funds are **stuck with no fail-proof recovery**. Recommendation: add a timeout in `retryWithSwap()` after which assets refund to the user. Fixed `7c700650`.

## [MEDIUM] M-3 Transfers where `dstEid == HUB_EID` will fail
Context: `OVaultComposer.sol#L130-145, L149-157, L163-172, L177-189`

`refund()`, `retryWithSwap()`, `retry()` use `_send()`, but `lzCompose()` uses `send()` which has extra same-chain handling that `_send()` lacks:
```solidity
if (_sendParam.dstEid == HUB_EID) {
    address _receiver = _sendParam.to.bytes32ToAddress();
    IERC20(IOFT(_oft).token()).transfer(_receiver, _sendParam.amountLD);
    if (msg.value > 0) { (bool sent,) = _receiver.call{value: msg.value}(""); require(sent); }
    emit SentOnHub(_receiver, _oft, _sendParam.amountLD);
    return;
}
```
So when `dstEid == HUB_EID`, `_send()` attempts a cross-chain send to the same chain → `NoPeer`. Also `send()` can fail via `transfer()` (e.g. USDC blocklist) or `_receiver.call()` reverting in a contract `receive()`. Recommendation: use `this.send()` instead of `_send()`, and add a slippage check for the `dstEid==HUB_EID` retry path. Fixed `7c700650`.

## [MEDIUM] M-4 `msg.value` can be lost
Context: `OVaultComposer.sol#L45, L149, L163, L177` (found by project)

`lzCompose()` is supplied native tokens for the onward transfer. If it fails and a `failedMessages[]` record is created, the `msg.value` is stranded in the composer; `refund()/retry()/retryWithSwap()` require supplying native again. Recommendation: register supplied `msg.value` in `failedMessages[]` and reuse it. Fixed PR 1600.

## [MEDIUM] M-5 Different slippage checks can lead to stuck funds
Context: `OVaultComposer.sol#L116-127` (found by project)

`executeOVaultAction()` has a `minAmount` check, but `LayerZeroEndpoint::send()` checks against `_removeDust(_amountLD)` in `_debitView()`:
```solidity
amountSentLD = _removeDust(_amountLD);
if (amountSentLD < _minAmountLD) revert SlippageExceeded(amountSentLD, _minAmountLD);
```
A specific amount can pass `executeOVaultAction()` but fail `send()` → won't be sent. Recommendation: use the same (dust-aware) check in `executeOVaultAction()`. Fixed `dc38170b`.

> dreUSD: this is the 18→6 `_removeDust` / `sharedDecimals` truncation interacting with slippage — trace the composer overrides' min-amount checks against `_debitView`.

---

## [LOW]
- **L-1 Override `decimals()` to honor decimal offset** (`OVault.sol#L10`): overriding `_decimalsOffset()` makes `decimals()` return e.g. 27 while shares still mint at 18 → integrator confusion. Tied to M-1. Fixed `fae8a363`.
- **L-2 `transfer()` is used** (`L136`): `send()` uses `transfer()` without checking return value → undetected failed transfers. Use `safeTransfer()`. Fixed `d8c72799`.
- **L-3 `tx.origin` used as refundAddress** (`L194-196`): with ERC-4337 / EIP-7702, `tx.origin` may be a bundler → refund misrouted. Acknowledged (executor is EOA); protocols using bundlers must override `_send()`.
- **L-4 No checks on `_extraOptions`** (`L149, L163, L177`): `refund()/retryWithSwap()/retry()` don't validate `_extraOptions` → griefing via huge gas/native values. Fixed `7c700650`.

## [GAS] G-1 `refundSendParam` stored but unused in `retry()` (`L45, L98-107, L163-174`) — store empty SendParam. Fixed `ff167304`.

## [INFO]
- I-1 Remove unused imports (`IOVaultComposer.sol#L5`).
- I-2 Redundant `SafeERC20` import in vault contracts.
- I-3 `retryWithSwap()` lacks `nonReentrant` (all other external fns except `lzCompose()` have it). Fixed `b7c7d540`.
- I-4 Inaccurate `retry()` docs — `retry()` only fires when `oft.send()` fails on gas; "peer not set" goes to `refund()`; other reverts: USDC blocklist in `transfer()`, contract `receive()` revert in `_receiver.call()`.
- I-5 Inaccessible (try/catch-only) functions in interface.
- I-6 Slippage check inside `_send()` in `retryWithSwap()` not obvious.
- I-7 Typos.
- I-8 Add constructor checks: `IOFT(_shareOFT).token() == OVAULT` and `IOFT(_assetOFT).token() == OVAULT.asset()`.
- I-9 Insufficient testing — recommends pigeon-based near-mainnet integration tests for OFT/LZ edge cases.
