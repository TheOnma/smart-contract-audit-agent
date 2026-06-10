// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MonotonicityCheck
 * @notice Halmos symbolic execution checks for approximation function monotonicity.
 *
 * Usage:
 *   halmos --contract MonotonicityCheck --function check_wExpMonotone --loop 3
 *   halmos --contract MonotonicityCheck --function check_tickToPriceMonotone --loop 3
 *
 * Halmos returns:
 *   UNSAT = property holds for ALL inputs in the bounded range (proven)
 *   SAT   = counterexample found — Halmos gives you the exact tick/input values (your bug)
 *
 * Key difference from fuzzing: Halmos proves the property holds, not just that it
 * hasn't failed in N random trials. For a bounded range like [0, MAX_TICK=5820],
 * UNSAT from Halmos is a proof.
 *
 * TODO: Import your protocol's math library and fill in the function calls.
 */

import {Test} from "forge-std/Test.sol";

// [TODO] Import your math library
// import {TickLib} from "src/libraries/TickLib.sol";

contract MonotonicityCheck is Test {

    // [TODO] Set your protocol's constants
    // uint256 constant MAX_TICK    = 5820;
    // int256  constant LN_DELTA    = 4987541511e9; // ln(1.005) * 1e18
    // int256  constant LN_HALF_MAX = int256(LN_DELTA * int256(MAX_TICK / 2));

    // ── wExp monotonicity ────────────────────────────────────────────────────

    /**
     * @notice Proves wExp is monotonically non-decreasing over the valid tick input range.
     * If SAT: Halmos returns concrete (a, b) where wExp(a) < wExp(b) despite a > b.
     */
    function check_wExpMonotone(int256 a, int256 b) external pure {
        // [TODO] Uncomment and fill in bounds
        // int256 lo = LN_DELTA * (int256(MAX_TICK / 2) - int256(MAX_TICK));
        // int256 hi = LN_HALF_MAX;
        // vm.assume(a >= lo && a <= hi);
        // vm.assume(b >= lo && b <= hi);
        vm.assume(a > b);
        // assert(TickLib.wExp(a) >= TickLib.wExp(b));
    }

    // ── tickToPrice monotonicity ─────────────────────────────────────────────

    /**
     * @notice Proves tickToPrice is strictly monotone over [0, MAX_TICK).
     * Direction: check which way your protocol goes (lower tick = higher or lower price).
     */
    function check_tickToPriceMonotone(uint16 t1, uint16 t2) external view {
        // [TODO] Uncomment and set direction
        // vm.assume(t1 < MAX_TICK && t2 < MAX_TICK);
        vm.assume(t1 < t2);
        // For Morpho Midnight: higher tick = higher price
        // assert(midnight.tickToPrice(t2) >= midnight.tickToPrice(t1));
    }

    // ── lossFactor formula: never hits max ───────────────────────────────────

    /**
     * @notice Proves the lossFactor update formula never produces type(uint128).max
     * when totalUnits > badDebt (the invariant that should hold).
     */
    function check_lossFactorNeverMax(
        uint128 lossFactor,
        uint128 totalUnits,
        uint128 badDebt
    ) external pure {
        vm.assume(totalUnits > badDebt);   // key precondition
        vm.assume(totalUnits > 0);
        vm.assume(lossFactor < type(uint128).max);

        // Replicate the formula from your protocol:
        // [TODO] Replace with your exact formula
        // uint256 maxU    = type(uint128).max;
        // uint256 factor  = ((maxU - lossFactor) * (totalUnits - badDebt)) / totalUnits;
        // uint256 newLoss = maxU - factor;
        // assert(newLoss < type(uint128).max);
    }

    // ── mulDivDown: result bounded by dividend ───────────────────────────────

    /**
     * @notice Proves mulDivDown(x, y, d) * d <= x * y (rounding is truly downward).
     * Halmos can exhaustively verify this over all 128-bit inputs.
     */
    function check_mulDivDownRoundingDirection(
        uint128 x,
        uint128 y,
        uint128 d
    ) external pure {
        vm.assume(d > 0);
        uint256 result = (uint256(x) * y) / d;
        assert(result * d <= uint256(x) * y);
    }

    // ── Add your protocol-specific bounded proofs below ──────────────────────
    // Good candidates:
    //   - Price round-trip: priceToTick(tickToPrice(t)) is within tick spacing of t
    //   - Asset/unit conversion round-trip is exact
    //   - Settlement fee interpolation is bounded by breakpoint values
    //   - Health factor never overflows for valid positions
}
