# False Positives — OpenZeppelin ERC4626

## [INFO] Standard ERC20 transferFrom with checks-effects-interactions — not exploitable

Triaged 2026-08: reviewed a plain OZ-style `transferFrom`/`_transfer` against
the corpus ERC20 findings (allowance bypass, missing balance check, state
updates after external calls). This implementation follows
checks-effects-interactions: the allowance is spent before the transfer and
both zero-address and balance checks run before any state change, so it is a
false positive — safe by design:

```solidity
function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
    address spender = _msgSender();
    _spendAllowance(from, spender, amount);
    _transfer(from, to, amount);
    return true;
}
function _transfer(address from, address to, uint256 amount) internal virtual {
    require(from != address(0), "ERC20: transfer from the zero address");
    require(to != address(0), "ERC20: transfer to the zero address");
    uint256 fromBalance = _balances[from];
    require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
    unchecked { _balances[from] = fromBalance - amount; }
    _balances[to] += amount;
    emit Transfer(from, to, amount);
}
```

There is no external call in the transfer path (no reentrancy window), the
allowance is decremented before the balance moves, and the balance check runs
before any state change. Not a vulnerability — do not report.
