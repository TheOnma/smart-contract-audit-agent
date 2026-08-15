# False Positives — Oracle Finding Class (Solodit)

## [LOW] Chainlink read with min/max bounds + staleness + decimals guards — not exploitable

Triaged 2026-08: reviewed `ETHOracle.getLatestPrice()` against the corpus
oracle findings (missing min/max bounds, stale price heartbeat, incorrect
decimals scaling). This instance applies all three guards, so it is a false
positive — safe by design:

```solidity
function getLatestPrice() public view override returns (IOracle.Price memory price) {
    (, int256 answer, , uint256 updatedAt, ) = _ethPriceFeed.latestRoundData();
    if (answer <= int256(_minAnswer)) revert InvalidPriceFromOracle();
    if (answer >= int256(_maxAnswer)) revert InvalidPriceFromOracle();
    if (block.timestamp - updatedAt > _stalePeriod) revert StalePrice();
    price.price = uint256(answer) * 1e10; // 8-decimal feed -> 18 decimals
    price.lastUpdate = updatedAt;
}
```

Every check that the real findings were missing is present here: the answer is
bounded by `_minAnswer`/`_maxAnswer`, freshness is enforced against
`_stalePeriod`, and the 8-decimal feed is scaled correctly to 18 decimals. The
price cannot be manipulated via an out-of-range or stale answer. Not a
vulnerability — do not report.
