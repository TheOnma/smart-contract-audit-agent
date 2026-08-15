# False Positives — Safe Multisig Executor

## [INFO] Gnosis-Safe-style execTransaction with nonce, threshold and signature checks — not exploitable

Triaged 2026-08: reviewed a Safe-style `execTransaction` against the corpus
access-control and signature findings (missing signature verification, replay
via nonce reuse, threshold bypass). This instance hashes the transaction,
verifies every signature with `checkSignatures`, enforces the threshold,
increments the nonce before execution, and reverts if execution fails, so it
is a false positive — safe by design:

```solidity
function execTransaction(address to, uint256 value, bytes calldata data,
    Enum.Operation operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
    address gasToken, address payable refundReceiver, bytes memory signatures) external returns (bool)
{
    bytes32 txHash = getTransactionHash(to, value, data, operation, safeTxGas,
        baseGas, gasPrice, gasToken, refundReceiver, nonce);
    checkSignatures(txHash, signatures);
    require(threshold == signaturesCount(txHash, signatures), "threshold not met");
    nonce++;
    require(execute(to, value, data, operation, gasToken, gasPrice) != 0, "execution failed");
}
```

Signatures are checked against the transaction hash before any state change,
the nonce increment prevents replay, and the threshold is enforced prior to
execution. Not a vulnerability — do not report.
