// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MockCallbackReceiver
 * @notice Configurable mock for onBuy / onSell / onFlashLoan callbacks.
 *
 * Without this, the fuzzer can never reach callback execution paths.
 * Three modes:
 *   HONEST    — transfers required tokens back (normal user behavior)
 *   REENTER   — tries to call back into the protocol during the callback
 *   GRIEF     — does nothing, causing the outer call to revert
 *
 * Usage in harness:
 *   MockCallbackReceiver buyerCb  = new MockCallbackReceiver(Mode.HONEST,  address(midnight));
 *   MockCallbackReceiver sellerCb = new MockCallbackReceiver(Mode.HONEST,  address(midnight));
 *   MockCallbackReceiver griefer  = new MockCallbackReceiver(Mode.GRIEF,   address(midnight));
 *   MockCallbackReceiver reenter  = new MockCallbackReceiver(Mode.REENTER, address(midnight));
 *
 * TODO: Replace IProtocol with your protocol's interface and adapt callback signatures.
 */

interface IProtocol {
    // TODO: add the functions the attacker would call in a reentrancy attempt
    // e.g.: function take(...) external;
    // e.g.: function liquidate(...) external;
    // e.g.: function flashLoan(...) external;
}

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external returns (uint256);
}

contract MockCallbackReceiver {
    enum Mode { HONEST, REENTER, GRIEF }

    Mode    public mode;
    address public protocol;

    // Configurable reentrant call (set before fuzzer calls that reach the callback)
    bytes public reenterCalldata;
    bool  public reenterCallSucceeded;

    // Track callback invocations for assertion in invariant tests
    uint256 public onBuyCalls;
    uint256 public onSellCalls;
    uint256 public onFlashLoanCalls;

    constructor(Mode _mode, address _protocol) {
        mode     = _mode;
        protocol = _protocol;
    }

    function setMode(Mode _mode) external { mode = _mode; }
    function setReenterCalldata(bytes calldata data) external { reenterCalldata = data; }

    // ── onBuy callback ──────────────────────────────────────────────────────
    // TODO: replace signature with your protocol's actual onBuy callback signature
    function onBuy(
        bytes32 /* id */,
        uint256 /* units */,
        uint256 assets,
        address loanToken,
        bytes calldata /* data */
    ) external returns (bytes32 magicValue) {
        onBuyCalls++;

        if (mode == Mode.GRIEF) revert("griefed");

        if (mode == Mode.REENTER && reenterCalldata.length > 0) {
            (bool ok,) = protocol.call(reenterCalldata);
            reenterCallSucceeded = ok;
            // Don't revert — let the outer call continue to see if it catches the inconsistency
        }

        if (mode == Mode.HONEST) {
            // Transfer required assets to the protocol
            IERC20Minimal(loanToken).transfer(protocol, assets);
        }

        // TODO: return your protocol's CALLBACK_SUCCESS magic value
        // e.g.: return keccak256("morpho.midnight.callbackSuccess");
        return keccak256("callbackSuccess");
    }

    // ── onSell callback ─────────────────────────────────────────────────────
    // TODO: replace signature with your protocol's actual onSell callback signature
    function onSell(
        bytes32 /* id */,
        uint256 /* units */,
        uint256 collateralToSupply,
        address collateralToken,
        bytes calldata /* data */
    ) external returns (bytes32 magicValue) {
        onSellCalls++;

        if (mode == Mode.GRIEF) revert("griefed");

        if (mode == Mode.REENTER && reenterCalldata.length > 0) {
            (bool ok,) = protocol.call(reenterCalldata);
            reenterCallSucceeded = ok;
        }

        if (mode == Mode.HONEST && collateralToSupply > 0) {
            IERC20Minimal(collateralToken).transfer(protocol, collateralToSupply);
        }

        return keccak256("callbackSuccess");
    }

    // ── onFlashLoan callback ────────────────────────────────────────────────
    // TODO: replace signature with your protocol's actual flash loan callback
    function onFlashLoan(
        address /* initiator */,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata /* data */
    ) external returns (bytes32 magicValue) {
        onFlashLoanCalls++;

        if (mode == Mode.GRIEF) revert("griefed");

        if (mode == Mode.REENTER && reenterCalldata.length > 0) {
            (bool ok,) = protocol.call(reenterCalldata);
            reenterCallSucceeded = ok;
        }

        if (mode == Mode.HONEST) {
            // Repay flash loan + fee
            IERC20Minimal(token).transfer(protocol, amount + fee);
        }

        return keccak256("callbackSuccess");
    }

    // Allow receiving ERC20 tokens
    receive() external payable {}
}
