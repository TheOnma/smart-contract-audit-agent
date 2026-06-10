/**
 * Certora rule: wExp (or equivalent Taylor approximation) is monotonically non-decreasing.
 *
 * This rule closes the gap left by NONDET treatment of tickToPrice in most specs.
 * If this rule FAILS, Certora gives you a concrete counterexample (tick pair).
 *
 * Usage:
 *   certoraRun src/libraries/TickLib.sol \
 *     --verify TickLib:certora/audit_rules/wexp_monotonicity.spec \
 *     --solc solc-0.8.34
 *
 * TODO: Update method name and bounds to match your protocol.
 */

methods {
    // [TODO] Map your approximation function
    // function wExp(int256) external returns (uint256) envfree;
    // function tickToPrice(uint256) external returns (uint256) envfree;
}

// [TODO] Set your protocol's valid input bounds
definition MIN_INPUT() returns int256 = -2910 * 4987541511; // LN_DELTA * (MAX_TICK/2 - MAX_TICK)
definition MAX_INPUT() returns int256 =  2910 * 4987541511; // LN_DELTA * MAX_TICK/2

/**
 * wExp is monotonically non-decreasing over the valid tick input range.
 * For all x > y in [MIN_INPUT, MAX_INPUT]: wExp(x) >= wExp(y)
 */
rule wExpMonotonicity(int256 x, int256 y) {
    require x >= MIN_INPUT() && x <= MAX_INPUT();
    require y >= MIN_INPUT() && y <= MAX_INPUT();
    require x > y;
    // assert wExp(x) >= wExp(y);  // [TODO] uncomment
}

/**
 * tickToPrice is strictly monotone over [0, MAX_TICK).
 * Direction: lower tick < higher tick means lower price < higher price (protocol-specific).
 */
rule tickToPriceMonotone(uint256 t1, uint256 t2) {
    require t1 < 5820 && t2 < 5820;  // [TODO] replace with MAX_TICK constant
    require t1 < t2;
    // assert tickToPrice(t1) < tickToPrice(t2);  // [TODO] uncomment, verify direction
}
