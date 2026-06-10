/**
 * Certora rule: lossFactor never reaches type(uint128).max after a legitimate liquidation.
 *
 * This closes the gap not covered by the existing LossFactor.spec — which proves
 * loss factor increases but does NOT bound it away from type(uint128).max.
 *
 * If this rule FAILS: the lossFactor saturation bug is real and provably reachable.
 *
 * TODO: Update contract name, method signatures, and state variables.
 */

methods {
    // [TODO] Map your protocol's liquidate function
    // function liquidate(bytes32 id, address borrower, uint256 repaidUnits,
    //                    uint256 seizedCollateralIndex, bytes data) external;

    // Getters for market state
    // function marketState(bytes32) external returns (MarketState memory) envfree;
}

/**
 * After any call to liquidate(), lossFactor < type(uint128).max,
 * provided totalUnits > 0 going in.
 *
 * Preconditions reflect the invariant that should hold before liquidation:
 *   - market exists (totalUnits > 0)
 *   - lossFactor is not already maxed (if it's maxed going in, that's a separate bug)
 */
rule lossFactorNeverMax(env e) {
    bytes32 id;

    // Pre-state: valid market
    // require marketState(id).totalUnits > 0;  // [TODO] uncomment
    // require marketState(id).lossFactor < max_uint128;  // [TODO] uncomment

    // [TODO] Call liquidate
    // liquidate(e, id, _, _, _, _);

    // Post-state: lossFactor must not have saturated
    // assert marketState(id).lossFactor < max_uint128,
    //        "lossFactor saturated to max after liquidation";  // [TODO] uncomment
}

/**
 * Variant: even in the extreme case badDebt = totalUnits - 1,
 * lossFactor stays below max.
 *
 * This is the specific edge case from the audit finding.
 */
rule lossFactorNeverMaxNearTotalUnits(env e) {
    bytes32 id;

    // [TODO] Set up near-total-bad-debt state and verify same property
    // uint128 totalUnits = marketState(id).totalUnits;
    // uint128 badDebt = totalUnits - 1;  // worst case
    // require totalUnits > 1;
    // require marketState(id).lossFactor < max_uint128;

    // [TODO] Trigger liquidation that would process badDebt = totalUnits - 1
    // liquidate(e, id, _, _, _, _);

    // assert marketState(id).lossFactor < max_uint128;  // [TODO] uncomment
}
