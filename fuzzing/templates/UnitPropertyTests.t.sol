// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title UnitPropertyTests
 * @notice Stateless property (fuzz) tests for pure math functions.
 *
 * Run with high fuzz count:
 *   forge test --match-path "test/audit/UnitPropertyTests.t.sol" --fuzz-runs 100000 -vv
 *
 * These tests have no state setup and run fast. They find arithmetic edge cases
 * that stateful invariant tests may never reach through random call sequences.
 *
 * TODO sections:
 *   1. Import your protocol's math libraries
 *   2. Fill in the actual function calls (replace PLACEHOLDER)
 *   3. Add protocol-specific properties at the bottom
 */

import {Test} from "forge-std/Test.sol";

// TODO: import your protocol's math libraries
// import {TickLib}  from "src/libraries/TickLib.sol";
// import {UtilsLib} from "src/libraries/UtilsLib.sol";

contract UnitPropertyTests is Test {

    // ── Constants (TODO: match your protocol) ────────────────────────────────
    // uint256 constant WAD        = 1e18;
    // uint256 constant MAX_TICK   = 5820;
    // int256  constant LN_DELTA   = 4987541511e9; // ln(1.005) * 1e18
    // uint256 constant PRICE_STEP = 1e12;

    // ────────────────────────────────────────────────────────────────────────
    // GROUP 1: mulDiv rounding properties
    // ────────────────────────────────────────────────────────────────────────

    /// mulDivDown <= mulDivUp always
    function testFuzz_mulDivOrdering(uint128 x, uint128 y, uint128 d) public pure {
        vm.assume(d > 0);
        uint256 down = (uint256(x) * y) / d;
        uint256 up   = (uint256(x) * y + d - 1) / d;
        assertLe(down, up, "mulDivDown must be <= mulDivUp");
    }

    /// mulDivDown result * d <= x * y (never overestimates)
    function testFuzz_mulDivDownNeverOverestimates(uint128 x, uint128 y, uint128 d) public pure {
        vm.assume(d > 0);
        uint256 result = (uint256(x) * y) / d;
        assertLe(result * d, uint256(x) * y, "mulDivDown overestimates");
    }

    /// mulDivUp result * d >= x * y (never underestimates)
    function testFuzz_mulDivUpNeverUnderestimates(uint128 x, uint128 y, uint128 d) public pure {
        vm.assume(d > 0);
        uint256 up = (uint256(x) * y + d - 1) / d;
        // up * d might overflow uint256 for very large inputs — bound accordingly
        vm.assume(up <= type(uint256).max / d);
        assertGe(up * d, uint256(x) * y, "mulDivUp underestimates");
    }

    /// mulDivDown is monotone in x: if x1 > x2, result1 >= result2
    function testFuzz_mulDivDownMonotoneInX(
        uint128 x1, uint128 x2, uint64 y, uint64 d
    ) public pure {
        vm.assume(d > 0 && x1 >= x2);
        uint256 r1 = (uint256(x1) * y) / d;
        uint256 r2 = (uint256(x2) * y) / d;
        assertGe(r1, r2, "mulDivDown not monotone in x");
    }

    // ────────────────────────────────────────────────────────────────────────
    // GROUP 2: Approximation function monotonicity
    // ────────────────────────────────────────────────────────────────────────

    /// TODO: wExp (or equivalent) must be monotonically non-decreasing
    /// Replace TickLib.wExp with your protocol's approximation function.
    // function testFuzz_wExpMonotone(int256 a, int256 b) public pure {
    //     // Bound to valid input range: LN_DELTA * (MAX_TICK/2 - MAX_TICK) to LN_DELTA * MAX_TICK/2
    //     int256 lo = LN_DELTA * (int256(MAX_TICK / 2) - int256(MAX_TICK));
    //     int256 hi = LN_DELTA * int256(MAX_TICK / 2);
    //     vm.assume(a >= lo && a <= hi);
    //     vm.assume(b >= lo && b <= hi);
    //     vm.assume(a > b);
    //     assertGe(TickLib.wExp(a), TickLib.wExp(b), "wExp not monotone");
    // }

    /// TODO: tickToPrice must be strictly monotone (lower tick = higher price or vice versa)
    /// Fill in direction based on your protocol's design.
    // function testFuzz_tickToPriceMonotone(uint16 t1, uint16 t2) public view {
    //     vm.assume(t1 < MAX_TICK && t2 < MAX_TICK && t1 < t2);
    //     // For Morpho Midnight: higher tick = higher price
    //     assertLt(
    //         tickLib.tickToPrice(t1),
    //         tickLib.tickToPrice(t2),
    //         "tickToPrice not monotone"
    //     );
    // }

    // ────────────────────────────────────────────────────────────────────────
    // GROUP 3: Scaling / loss factor arithmetic
    // ────────────────────────────────────────────────────────────────────────

    /// After applying a loss factor < max, credit must be <= original credit
    function testFuzz_lossCreditNeverExceedsOriginal(
        uint128 credit,
        uint128 oldLoss,
        uint128 newLoss
    ) public pure {
        // Simulate: newCredit = credit * (max - newLoss) / (max - oldLoss)
        vm.assume(oldLoss < type(uint128).max);
        vm.assume(newLoss >= oldLoss); // loss factor only increases
        uint256 maxU  = type(uint128).max;
        uint256 denom = maxU - oldLoss;
        vm.assume(denom > 0);
        uint256 newCredit = (uint256(credit) * (maxU - newLoss)) / denom;
        assertLe(newCredit, credit, "slashed credit exceeds original");
    }

    /// lossFactor update formula: result < type(uint128).max when totalUnits > badDebt
    function testFuzz_lossFactorNeverMaxWhenPartialBadDebt(
        uint128 lossFactor,
        uint128 totalUnits,
        uint128 badDebt
    ) public pure {
        vm.assume(totalUnits > badDebt);  // key precondition
        vm.assume(totalUnits > 0);
        vm.assume(lossFactor < type(uint128).max);

        // Replicate the formula:
        // newLoss = max - (max - lossFactor) * (totalUnits - badDebt) / totalUnits
        uint256 maxU   = type(uint128).max;
        uint256 factor = ((maxU - lossFactor) * (totalUnits - badDebt)) / totalUnits;
        uint256 newLoss = maxU - factor;

        assertLt(newLoss, type(uint128).max, "lossFactor hit max despite totalUnits > badDebt");
    }

    // ────────────────────────────────────────────────────────────────────────
    // GROUP 4: Settlement fee interpolation
    // ────────────────────────────────────────────────────────────────────────

    /// Linear interpolation between two breakpoints is bounded by both
    function testFuzz_linearInterpBounded(
        uint256 feeA, uint256 feeB,
        uint256 timeA, uint256 timeB,
        uint256 t
    ) public pure {
        vm.assume(timeB > timeA);
        vm.assume(t >= timeA && t <= timeB);
        vm.assume(feeA <= 1e18 && feeB <= 1e18); // fees are fractions of WAD

        uint256 lo = feeA < feeB ? feeA : feeB;
        uint256 hi = feeA > feeB ? feeA : feeB;

        // interpolated = feeA + (feeB - feeA) * (t - timeA) / (timeB - timeA)
        uint256 interp;
        if (feeB >= feeA) {
            interp = feeA + (feeB - feeA) * (t - timeA) / (timeB - timeA);
        } else {
            interp = feeA - (feeA - feeB) * (t - timeA) / (timeB - timeA);
        }

        assertGe(interp, lo, "interpolation below lower bound");
        assertLe(interp, hi, "interpolation above upper bound");
    }

    // ────────────────────────────────────────────────────────────────────────
    // GROUP 5: Bitmap operations
    // ────────────────────────────────────────────────────────────────────────

    /// setBit then clearBit returns original
    function testFuzz_bitmapSetClearRoundtrip(uint128 bitmap, uint8 bit) public pure {
        vm.assume(bit < 128);
        uint128 set     = uint128(bitmap | (1 << bit));
        uint128 cleared = uint128(set & ~(uint128(1) << bit));
        assertEq(cleared, bitmap & ~(uint128(1) << bit), "set/clear round-trip failed");
    }

    /// Setting already-set bit is idempotent
    function testFuzz_setBitIdempotent(uint128 bitmap, uint8 bit) public pure {
        vm.assume(bit < 128);
        uint128 set1 = uint128(bitmap | (1 << bit));
        uint128 set2 = uint128(set1  | (1 << bit));
        assertEq(set1, set2, "setBit not idempotent");
    }

    /// Clearing already-clear bit is idempotent
    function testFuzz_clearBitIdempotent(uint128 bitmap, uint8 bit) public pure {
        vm.assume(bit < 128);
        uint128 cleared1 = uint128(bitmap & ~(uint128(1) << bit));
        uint128 cleared2 = uint128(cleared1 & ~(uint128(1) << bit));
        assertEq(cleared1, cleared2, "clearBit not idempotent");
    }

    // ────────────────────────────────────────────────────────────────────────
    // GROUP 6: Protocol-specific properties (TODO: add yours here)
    // ────────────────────────────────────────────────────────────────────────

    // Add properties specific to your protocol's math here.
    // Good candidates:
    //   - Price round-trip: priceToTick(tickToPrice(t)) == t (or within spacing)
    //   - Asset/unit conversion round-trip
    //   - Fee calculation bounds
    //   - Health factor computation bounds
}
