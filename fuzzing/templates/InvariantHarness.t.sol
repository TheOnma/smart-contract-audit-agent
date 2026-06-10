// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title InvariantHarness
 * @notice Multi-actor stateful invariant test harness template.
 *
 * Run:
 *   forge test --match-path "test/audit/InvariantHarness.t.sol" \
 *              --invariant-runs 500 --invariant-depth 50 -vv
 *
 * Design principles:
 *   - 5 actors with distinct roles: each actor calls protocol functions from their perspective
 *   - Ghost state tracks expected values independently of the protocol
 *   - Invariants compare ghost state against actual protocol state
 *   - MockCallbackReceiver enables fuzzing all callback paths
 *   - targetSelector limits fuzzer to meaningful call sequences
 *
 * TODO sections marked with [TODO] — fill in before running.
 */

import {Test}     from "forge-std/Test.sol";
import {StdUtils} from "forge-std/StdUtils.sol";

// [TODO] Import your protocol + tokens
// import {Midnight}     from "src/Midnight.sol";
// import {ERC20Mock}    from "test/mocks/ERC20Mock.sol";
import {MockCallbackReceiver} from "./MockCallbackReceiver.sol";

contract InvariantHarness is Test {

    // ── Contracts [TODO: deploy in setUp] ────────────────────────────────────
    // Midnight midnight;
    // ERC20Mock loanToken;
    // ERC20Mock collateralToken;

    // ── Actors ───────────────────────────────────────────────────────────────
    address maker      = makeAddr("maker");
    address taker      = makeAddr("taker");
    address liquidator = makeAddr("liquidator");
    address feeClaimer = makeAddr("feeClaimer");
    address attacker   = makeAddr("attacker");  // acts adversarially

    // ── Callbacks ────────────────────────────────────────────────────────────
    MockCallbackReceiver honestBuyer;
    MockCallbackReceiver honestSeller;
    MockCallbackReceiver reentrantAttacker;

    // ── Ghost state (tracks what SHOULD be true) ─────────────────────────────
    uint256 ghostSumCredits;          // sum of all position.credit
    uint256 ghostSumDebts;            // sum of all position.debt
    uint128 ghostPrevLossFactor;      // for monotonicity check
    mapping(address => mapping(bytes32 => uint256)) ghostConsumed; // for anti-replay check

    // ── Market ID [TODO] ──────────────────────────────────────────────────────
    // bytes32 id;

    function setUp() external {
        // [TODO] Deploy protocol contracts
        // midnight  = new Midnight();
        // loanToken = new ERC20Mock("Loan", "LOAN", 18);
        // collateralToken = new ERC20Mock("Collateral", "COL", 18);

        // [TODO] Deploy callbacks
        // honestBuyer      = new MockCallbackReceiver(MockCallbackReceiver.Mode.HONEST,   address(midnight));
        // honestSeller     = new MockCallbackReceiver(MockCallbackReceiver.Mode.HONEST,   address(midnight));
        // reentrantAttacker = new MockCallbackReceiver(MockCallbackReceiver.Mode.REENTER, address(midnight));

        // [TODO] Create market, fund actors
        // loanToken.mint(maker, 1_000_000e18);
        // loanToken.mint(taker, 1_000_000e18);
        // collateralToken.mint(taker, 1_000_000e18);

        // [TODO] Seed interesting corner states for Echidna:
        //   - lossFactor near type(uint128).max
        //   - continuousFeeCredit > withdrawable
        //   - position at exact maturity timestamp
        //   - collateralBitmap saturated (all 16 slots used)

        // Tell Foundry which contracts to fuzz
        // targetContract(address(midnight));

        // Optionally restrict to meaningful selectors:
        // bytes4[] memory selectors = new bytes4[](4);
        // selectors[0] = midnight.take.selector;
        // selectors[1] = midnight.liquidate.selector;
        // selectors[2] = midnight.repay.selector;
        // selectors[3] = midnight.withdraw.selector;
        // targetSelector(FuzzSelector({addr: address(midnight), selectors: selectors}));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INVARIANTS — These must hold after EVERY call sequence
    // ═══════════════════════════════════════════════════════════════════════

    /// I-1: totalUnits covers all outstanding credits + protocol fee credit
    function invariant_totalUnitsSolvency() external view {
        // [TODO] Uncomment and fill in
        // MarketState memory s = midnight.marketState(id);
        // assertGe(
        //     s.totalUnits,
        //     ghostSumCredits + s.continuousFeeCredit,
        //     "I-1: totalUnits < credits + feeCredit"
        // );
    }

    /// I-2: lossFactor never reaches type(uint128).max
    function invariant_lossFactorNeverMax() external view {
        // [TODO]
        // assertLt(
        //     midnight.marketState(id).lossFactor,
        //     type(uint128).max,
        //     "I-2: lossFactor saturated"
        // );
    }

    /// I-3: lossFactor is monotonically non-decreasing
    function invariant_lossFactorMonotone() external {
        // [TODO]
        // uint128 current = midnight.marketState(id).lossFactor;
        // assertGe(current, ghostPrevLossFactor, "I-3: lossFactor decreased");
        // ghostPrevLossFactor = current;
    }

    /// I-4: Contract token balance covers all obligations
    function invariant_tokenBalance() external view {
        // [TODO]
        // uint256 balance     = loanToken.balanceOf(address(midnight));
        // uint256 withdrawable = midnight.marketState(id).withdrawable;
        // assertGe(balance, withdrawable, "I-4: balance < withdrawable");
    }

    /// I-5: No new debt can be created after maturity
    function invariant_noNewDebtPostMaturity() external view {
        // [TODO]
        // if (block.timestamp >= market.maturity) {
        //     Position memory pos = midnight.position(id, taker);
        //     assertLe(pos.debt, ghostDebtAtMaturity[taker], "I-5: debt increased post-maturity");
        // }
    }

    /// I-6: consumed[maker][group] only increases (anti-replay invariant)
    function invariant_consumedNeverDecreases() external view {
        // [TODO]
        // bytes32 group = keccak256("test-offer-group");
        // uint256 current = midnight.consumed(maker, group);
        // assertGe(current, ghostConsumed[maker][group], "I-6: consumed decreased");
    }

    /// I-7: A position's credit is always <= what it was before any lossFactor increase
    function invariant_creditOnlyDecreases() external view {
        // [TODO]
        // Position memory pos = midnight.position(id, maker);
        // assertLe(pos.credit, ghostInitialCredit[maker], "I-7: credit increased unexpectedly");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ACTOR FUNCTIONS — Called by the fuzzer to build call sequences
    // ═══════════════════════════════════════════════════════════════════════
    // These are wrapper functions that set up msg.sender and update ghost state.
    // The fuzzer calls these in random sequences to build protocol state.

    function actor_makerDeposit(uint256 units) external {
        // [TODO] maker deposits / creates offer
        // vm.prank(maker);
        // ... call protocol function ...
        // ghostSumCredits += units;
    }

    function actor_takerBorrow(uint256 units) external {
        // [TODO] taker borrows against collateral
        // vm.prank(taker);
        // ... call protocol's take() ...
        // ghostSumDebts += units;
    }

    function actor_liquidatorLiquidate(uint256 units) external {
        // [TODO] liquidator liquidates undercollateralized position
        // vm.prank(liquidator);
        // ... call protocol's liquidate() ...
    }

    function actor_attackerReenter(bytes calldata callData) external {
        // [TODO] attacker attempts reentrancy via callback
        // reentrantAttacker.setReenterCalldata(callData);
        // vm.prank(attacker);
        // ... call protocol function that triggers callback ...
    }

    function actor_feeClaimerClaim() external {
        // [TODO] feeClaimer claims accumulated continuous fee
        // vm.prank(feeClaimer);
        // ... call claimContinuousFee() ...
    }
}
