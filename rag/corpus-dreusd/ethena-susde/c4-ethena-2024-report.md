---
sponsor: "Ethena Labs"
slug: "2024-11-ethena-labs"
date: "2024-12-02" 
title: "Ethena Labs Invitational"
findings: "https://github.com/code-423n4/2024-11-ethena-labs-findings/issues"
contest: 463
---

# Overview

## About C4

Code4rena (C4) is an open organization consisting of security researchers, auditors, developers, and individuals with domain expertise in smart contracts.

A C4 audit is an event in which community participants, referred to as Wardens, review, audit, or analyze smart contract logic in exchange for a bounty provided by sponsoring projects.

During the audit outlined in this document, C4 conducted an analysis of the Ethena Labs smart contract system. The audit took place between November 4—November 11 2024.

## Wardens

In Code4rena's Invitational audits, the competition is limited to a small group of wardens; for this audit, 5 wardens participated:

  1. [MrPotatoMagic](https://code4rena.com/@MrPotatoMagic)
  2. [SpicyMeatball](https://code4rena.com/@SpicyMeatball)
  3. [KupiaSec](https://code4rena.com/@KupiaSec)
  4. [K42](https://code4rena.com/@K42)
  5. [Topmark](https://code4rena.com/@Topmark)

This audit was judged by [EV_om](https://code4rena.com/@ev_om).

Final report assembled by [itsmetechjay](https://twitter.com/itsmetechjay).

# Summary

The C4 analysis yielded an aggregated total of 2 unique vulnerabilities. Of these vulnerabilities, 0 received a risk rating in the category of HIGH severity and 2 received a risk rating in the category of MEDIUM severity.

Additionally, C4 analysis included 5 reports detailing issues with a risk rating of LOW severity or non-critical. 

All of the issues presented here are linked back to their original finding.

# Scope

The code under review can be found within the [C4 Ethena Labs repository](https://github.com/code-423n4/2024-11-ethena-labs), and is composed of 4 smart contracts written in the Solidity programming language and includes 665 lines of Solidity code.

*Note: After the audit, the Ethena team updated the token name from UStb to USDtb per this [PR](https://github.com/ethena-labs/ethena-usdtb-contest/pull/3), but maintained the existing functionality.*

# Severity Criteria

C4 assesses the severity of disclosed vulnerabilities based on three primary risk categories: high, medium, and low/non-critical.

High-level considerations for vulnerabilities span the following key areas when conducting assessments:

- Malicious Input Handling
- Escalation of privileges
- Arithmetic
- Gas use

For more information regarding the severity criteria referenced throughout the submission review process, please refer to the documentation provided on [the C4 website](https://code4rena.com), specifically our section on [Severity Categorization](https://docs.code4rena.com/awarding/judging-criteria/severity-categorization).

# Medium Risk Findings (2)
## [[M-01] Blacklisted user can burn tokens during WHITELIST_ENABLED state](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/15)
*Submitted by [MrPotatoMagic](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/15), also found by [SpicyMeatball](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/3)*

Blacklisted user can burn tokens during WHITELIST_ENABLED state. This breaks the main invariant from the [README](https://github.com/code-423n4/2024-11-ethena-labs/tree/main#main-invariants). This could become an issue when the admin tries to redistribute the blacklisted user's UStb balance using `redistributeLockedAmount()` but the blacklisted user frontruns it with a burn.

### Proof of Concept

According to the comment [here](https://github.com/code-423n4/2024-11-ethena-labs/blob/e93ee09b10f900bd3be385f392c80920898bf53e/contracts/ustb/UStb.sol#L209), it is possible for an address to be whitelisted and blacklisted at the same.

During the WHITELIST_ENABLED state, the code block below is checked when burning tokens to ensure only whitelisted addresses can burn their tokens. But since blacklisted users also have the whitelisted role as per the comment above, the condition evaluates to true and allows the blacklisted address to burn tokens.

```solidity
File: UStb.sol
208:             } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
209:                 // whitelisted user can burn

```

### Recommended Mitigation Steps

Add the conditions `!hasRole(BLACKLISTED_ROLE, msg.sender)` and `!hasRole(BLACKLISTED_ROLE, from)` to the check.

**[iethena (Ethena Labs) disputed via duplicate issue #3 and commented](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/3#issuecomment-2479266803):**

> This can happen in 2 different variants:
> 1. A user is initially blacklisted but is later added to the whitelist without being removed from the blacklist
> 2. A user is initially whitelisted but is later added to the blacklist without being removed from the whitelist
>
> In both cases the user can burn their tokens when whitelist mode is enabled for the transfer state. The likelihood of falling into this state is high because the Blacklist Manager and Whitelist Manager are intended to be different entities and as such we cannot guarantee that they will coordinate to maintain a clean separation of the blacklist/whitelist roles. If a user with a whitelist and blacklist role simultaneously, chose to burn their tokens in whitelist transfer state mode, it would have a positive impact on the protocol overall as there would be excess collateral in the protocol. We therefore believe that this issue should be marked as low as there is no incentive for a user to outright burn their tokens, in fact if a user does so, all other users in the protocol will benefit, without causing a negative impact.
> 
> 
> Just to note that this was fixed in ethena-labs/ethena-ustb-contest/pull/2 based off of a different qa finding which ensures that whitelist/blacklist roles are mutually exclusive.

***

## [[M-02] Non-whitelisted users can burn UStb and redeem collateral during WHITELIST_ENABLED state](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/13)
*Submitted by [MrPotatoMagic](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/13)*

Non-whitelisted users can redeem collateral tokens and burn their UStb even when whitelist mode has been enabled on UStb contract. This breaks the main invariant mentioned in the [README](https://github.com/code-423n4/2024-11-ethena-labs/tree/main#additional-context).

### Proof of Concept

The below code block is from the `\_beforeTokenTransfer() function()`, which is called at the beginning of the ERC20 \_burn() internal function. When the transferState is WHITELIST_ENABLED, it should only allow whitelisted users to burn their UStb as mentioned under the main invariants in the [README](https://github.com/code-423n4/2024-11-ethena-labs/tree/main#additional-context). But since the `from` address is not checked to have the `WHITELISTED_ROLE` as well, the call goes through.

```solidity
File: UStb.sol
193:         } else if (transferState == TransferState.WHITELIST_ENABLED) {
194:            
195:             if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
```

### Recommended Mitigation Steps

Add ` hasRole(WHITELISTED_ROLE, from)  ` in the check.

**[iethena (Ethena Labs) disputed and commented](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/13#issuecomment-2479259765):**
 > The Redeemer has a special role in the protocol and it is seen as a non-issue that UStb can be redeemed from a non-whitelisted address while whitelist mode is enabled. As specified in [the Overview](https://github.com/code-423n4/2024-11-ethena-labs/tree/main?tab=readme-ov-file#overview) the redeem order is determined by and off-chain RFQ system, in which case the Redeemer will not provide a redemption quote if they chose not to.
> 
> For clarity, a non-whitelisted user cannot redeem collateral without the involvement of the Redeemer, as it is the Redeemer who submits the settlement transaction on-chain. We therefore argue that the likelihood of this happening is low. In addition, the impact to the protocol is low as the collateralization ratio of the minting contract would not be impacted and other users' positions are not impacted. Although this finding is informationally correct, we view the severity to be based on the fact that a non-whitelisted address can initiate a redemption without the involvement of a trusted party within the protocol which is not the case.
> 
> We suggest marking this finding as Low severity.
> 


**[EV_om (judge) commented](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/13#issuecomment-2481859546):**
 > One of the main invariants here was:
> 
> > Only whitelisted user can send/receive/burn UStb tokens in a `WHITELIST_ENABLED` transfer state.
> 
> The warden could not have known whether the off-chain Redeemer would only submit transactions for whitelisted addresses. Besides, the WHITELIST_MANAGER and the REDEEMER being different entities means there can always be race conditions on address (un-)whitelisting and redemption submission.
> 
> If the contract must enforce the invariant (which seems to not necessarily be the case), this must be done onchain. But for the purpose of the audit, Medium is appropriate.

***

# Low Risk and Non-Critical Issues

For this audit, 5 reports were submitted by wardens detailing low risk and non-critical issues. The [report highlighted below](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/12) by **KupiaSec** received the top score from the judge.

*The following wardens also submitted reports: [MrPotatoMagic](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/16), [K42](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/2), [Topmark](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/6), and [SpicyMeatball](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/4).*

| Issue ID | Issue Name                                                                 |
|----------|----------------------------------------------------------------------------|
| L-01 | The `addBlacklistAddress` and `addWhitelistAddress` functions do not check whether the user has opposite role |
| L-02 | In the constructor of `UStbMinting` contract, it does not set `ustb` |
| L-03 | The `_computeDomainSeparator` function incorrectly encodes `bytes32` variable as `string` type |
| L-04 | `differenceInBps` is calculated with a precision of 10^4 |
| L-05 | If the `collateral_asset` is native token, minting is unavailable even though redeeming is available. |
| L-06 | Most of the event parameters are of the `uint256` data type, but `uint128` variables are used when emitting them |
| L-07 | The`GATEKEEPER_ROLE` shouldn't be allowed to remove the `COLLATERAL_MANAGER_ROLE` |
| L-08 | Unnecessary check of `tokenConfig[asset].isActive` in the `_transferToBeneficiary` function. |
| L-09 | Non-blacklisted addresses can't burn `UStb` tokens in a `FULLY_ENABLED` transfer state if `address(0)` is blaklisted |
| L-10 | The `redistributeLockedAmount()` function does not verify if the address `to` possesses the `WHITELISTED_ROLE` when `WHITELIST_ENABLED`. |
| L-11 | There is no function available to transfer UStb from unwhitelisted users to whitelisted users. |
| L-12 | The `_beforeTokenTransfer()` function does not verify whether addresses are whitelisted when `WHITELIST_ENABLED` is set. |

## [L-01] The `addBlacklistAddress` and `addWhitelistAddress` functions do not check whether the user has opposite role

The [`addBlacklistAddress`](https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/UStb.sol#L73) function does not check whether the user has `WHITELISTED_ROLE`

```solidity
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            _grantRole(BLACKLISTED_ROLE, users[i]);
        }
    }
```

The [`addWhitelistAddress`](https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/UStb.sol#L91) function does not check whether the user has `BLACKLISTED_ROLE`

```solidity
    function addWhitelistAddress(address[] calldata users) external onlyRole(WHITELIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            _grantRole(WHITELISTED_ROLE, users[i]);
        }
    }
```

If `WHITELIST_MANAGER_ROLE` grants `WHITELISTED_ROLE` to blacklisted user and does not remove BLACKLISTED_ROLE, the user cannot transfer `UStb` token in `WHITELIST_ENABLED` state from [L205](https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/UStb.sol#L206).

```solidity
        } else if (
            hasRole(WHITELISTED_ROLE, msg.sender) &&
            hasRole(WHITELISTED_ROLE, from) &&
            hasRole(WHITELISTED_ROLE, to) &&
            !hasRole(BLACKLISTED_ROLE, msg.sender) &&
L206:       !hasRole(BLACKLISTED_ROLE, from) &&
            !hasRole(BLACKLISTED_ROLE, to)
        ) {
            // n.b. an address can be whitelisted and blacklisted at the same time
            // normal case
        } else {
            revert OperationNotAllowed();
        }
```

It is recommended to change the code as follows:

```diff
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
+           if (hasRole(WHITELISTED_ROLE, users[i]))
+               _revokeRole(WHITELISTED_ROLE, users[i]);
            _grantRole(BLACKLISTED_ROLE, users[i]);
        }
    }
    
    function addWhitelistAddress(address[] calldata users) external onlyRole(WHITELIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
+           if (hasRole(BLACKLISTED_ROLE, users[i]))
+               _revokeRole(BLACKLISTED_ROLE, users[i]);
            _grantRole(WHITELISTED_ROLE, users[i]);
        }
    }
```

## [L-02] In the constructor of `UStbMinting` contract, it does not set `ustb`

The constructor of `UStbMinting` contract does not set `ustb`, it checks whether `_assets[k]` is `address(ustb)` from L187

https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/UStbMinting.sol#L187

```solidity
L187:   if (tokenConfig[_assets[k]].isActive || _assets[k] == address(0) || _assets[k] == address(ustb)) {
            revert InvalidAssetAddress();
        }
```

Because initial value `ustb` is 0, `_assets[k] == address(ustb)` is same as `_assets[k] == address(0)`.
This means `_assets[k] == address(ustb)` is an unnecessary check.

Sets the initial `ustb` in the constructor of the `UStbMinting` contract.


## [L-03] The `_computeDomainSeparator` function incorrectly encodes `bytes32` variable as `string` type

The `EIP712_DOMAIN`'s `name` and `version` parameters are `string` type, and `EIP_712_NAME` and `EIP712_REVISION` are `bytes32` type.

```solidity
L28:    bytes32 private constant EIP712_DOMAIN =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
L56:    bytes32 private constant EIP_712_NAME = keccak256("EthenaUStbMinting");
L59:    bytes32 private constant EIP712_REVISION = keccak256("1");
```

The [_computeDomainSeparator](https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/UStbMinting.sol#L665) function encodes with inconsistent data type.
```solidity
        function _computeDomainSeparator() internal view returns (bytes32) {
L665:       return keccak256(abi.encode(EIP712_DOMAIN, EIP_712_NAME, EIP712_REVISION, block.chainid, address(this)));
        }
```
Ensure that the data types of the parameters `EIP712_DOMAIN`, `EIP_712_NAME`, and `EIP712_REVISION` match.

## [L-04] `differenceInBps` is calculated with a precision of 10^4

Since `STABLES_RATIO_MULTIPLIER` is 10,000, `differenceInBps` is calculated with a precision of 10^4.

https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/UStbMinting.sol#L568

```solidity
L568:     uint128 differenceInBps = (difference * STABLES_RATIO_MULTIPLIER) / ustbAmount;
```

It needs to calculate it with higher precision.

Sets the `STABLES_RATIO_MULTIPLIER` as higher value like `1e18`.

## [L-05] If the `collateral_asset` is native token, minting is unavailable even though redeeming is available.

In the `_transferCollateral` function, if the `collateral_asset` is native token, it reverts. This causes minting reverts.

```solidity
File: contracts\ustb\UStbMinting.sol
608:         if (!tokenConfig[asset].isActive || asset == NATIVE_TOKEN) revert UnsupportedAsset();
```

However, redeeming is available even though the `collateral_asset` is native token.

```solidity
    function _transferToBeneficiary(address beneficiary, address asset, uint128 amount) internal {
L:588:  if (asset == NATIVE_TOKEN) {
            if (address(this).balance < amount) revert InvalidAmount();
            (bool success, ) = (beneficiary).call{value: amount}("");
            if (!success) revert TransferFailed();
        } else {
            if (!tokenConfig[asset].isActive) revert UnsupportedAsset();
            IERC20(asset).safeTransfer(beneficiary, amount);
        }
    }
```

Improve the minting mechanism to allow native token.

## [L-06] Most of the event parameters are of the `uint256` data type, but `uint128` variables are used when emitting them

The `collateral_amount` of the `Mint` event are uint256 data type.

https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/IUStbMintingEvents.sol#L17

```solidity
    event Mint(
        string indexed order_id,
        address indexed benefactor,
        address indexed beneficiary,
        address minter,
        address collateral_asset,
L17:    uint256 collateral_amount,
        uint256 ustb_amount
    );
```

However `order.collateral_amount` is `uint128` data type in the `mint` function.

```solidity
        emit Mint(
            order.order_id,
            order.benefactor,
            order.beneficiary,
            msg.sender,
            order.collateral_asset,
L251:       order.collateral_amount,
            order.ustb_amount
        );
```

Ensure that the data types of the events and variables match.

## [L-07] The`GATEKEEPER_ROLE` shouldn't be allowed to remove the `COLLATERAL_MANAGER_ROLE`

From the [readme](https://github.com/code-423n4/2024-11-ethena-labs/blob/main/README.md), the `GATEKEEPER` has the ability to disable minting and redeeming.
| Role              | Description                                                                        |
|-------------------|------------------------------------------------------------------------------------|
| GATEKEEPER        | has the ability to disable minting and redeeming                                   |

However, in the codebase, the `GATEKEEPER_ROLE` can remove the `COLLATERAL_MANAGER_ROLE` from an account.
```solidity
File: contracts\ustb\UStbMinting.sol
379:     function removeCollateralManagerRole(address collateralManager) external onlyRole(GATEKEEPER_ROLE) {
380:         _revokeRole(`COLLATERAL_MANAGER_ROLE`, collateralManager);
381:     }
```
The `COLLATERAL_MANAGER_ROLE` can transfer an asset to a custody wallet using the `transferToCustody()` function.

It means that the `GATEKEEPER_ROLE` can remove the functionality to transfer assets to the custody wallet.

It is recommended to modify the code as follows:
```diff
File: contracts\ustb\UStbMinting.sol
-        function removeCollateralManagerRole(address collateralManager) external onlyRole(DEFAULT_ADMIN_ROLE) {
+        function removeCollateralManagerRole(address collateralManager) external onlyRole(GATEKEEPER_ROLE) {
380:         _revokeRole(`COLLATERAL_MANAGER_ROLE`, collateralManager);
381:     }
```

## [L-08] Unnecessary check of `tokenConfig[asset].isActive` in the `_transferToBeneficiary` function.

The `redeem` function has `belowMaxRedeemPerBlock` modifier and it checks `_config.isActive` is true from [L127](https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/UStbMinting.sol#L127).

```solidity
L127:        if (!_config.isActive) revert UnsupportedAsset();
```

The `redeem` function calls `_transferToBeneficiary` and it also checks `tokenConfig[asset].isActive` is true from L594.

```solidity
L594:            if (!tokenConfig[asset].isActive) revert UnsupportedAsset();
```

This is an unnecessary double check. It is recommended to remove the check.

## [L-09] Non-blacklisted addresses can't burn `UStb` tokens in a `FULLY_ENABLED` transfer state if `address(0)` is blaklisted

From the [Main invariants](https://github.com/code-423n4/2024-11-ethena-labs/blob/main/README.md):
> ### Main invariants
> - Only non-blacklisted addresses can send/receive/burn UStb tokens in a `FULLY_ENABLED` transfer state.

However, if `address(0)` is blacklisted, non-blacklisted addresses can't burn their tokens, which violates the main invariants.

It is recommended to modify the code as follows:
```diff
File: contracts\ustb\UStb.sol
176:             ) {
177:                 // redistributing - mint
+                } else if (
+                    !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)
+                ) {
+                    // burn
178:             } else if (
179:                 !hasRole(BLACKLISTED_ROLE, msg.sender) &&
```

## [L-10] The `redistributeLockedAmount()` function does not verify if the address `to` possesses the `WHITELISTED_ROLE` when `WHITELIST_ENABLED`.

When the state is `WHITELIST_ENABLED`, only addresses with the `WHITELISTED_ROLE` are permitted to receive UStb. However, in the `redistributeLockedAmount()` function, the only check performed is to ensure that the address to does not have the `BLACKLISTED_ROLE`. Consequently, redistribution to an unwhitelisted address is allowed.

https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/UStbMinting.sol#L111-L120

```solidity
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
112     if (hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```

Verify whether the address to has the `WHITELISTED_ROLE` when the state is `WHITELIST_ENABLED`.

## [L-11] There is no function available to transfer UStb from unwhitelisted users to whitelisted users.

The `redistributeLockedAmount()` function facilitates the transfer of UStb from a blacklisted user to an unblacklisted user. However, when the state is `WHITELIST_ENABLED`, there is no mechanism in place to transfer UStb from an unwhitelisted user to a whitelisted user.

https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/UStbMinting.sol#L111-L120

```solidity
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
112     if (hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```

Include a function to transfer UStb from an unwhitelisted user to a whitelisted user when the state is `WHITELIST_ENABLED`.

## [L-12] The `_beforeTokenTransfer()` function does not verify whether addresses are whitelisted when `WHITELIST_ENABLED` is set.

As noted in line 191, the function only checks if the address `to` is not blacklisted. Consequently, unwhitelisted users can still receive UStb when `WHITELIST_ENABLED` is active. This issue appears in several locations.

https://github.com/code-423n4/2024-11-ethena-labs/blob/main/contracts/ustb/UStb.sol#L165-L218

```solidity
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {

            ...

        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
191         } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (
                hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // redistributing - mint
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) &&
                hasRole(WHITELISTED_ROLE, from) &&
                hasRole(WHITELISTED_ROLE, to) &&
                !hasRole(BLACKLISTED_ROLE, msg.sender) &&
                !hasRole(BLACKLISTED_ROLE, from) &&
                !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // n.b. an address can be whitelisted and blacklisted at the same time
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 0 - Fully disabled transfers
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
    }
```

Include checks to ensure that the addresses are whitelisted.

**[iethena (Ethena Labs) acknowledged and commented](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/12#issuecomment-2480339994):**
 > Fixed L-01. L-02, L-08 in ethena-labs/ethena-ustb-contest/pull/2

**EV_om (judge) commented via private message to C4 staff:**
> L-01 Invalid
> L-02 Low
> L-03 Low
> L-04 Invalid
> L-05 Non-Critical
> L-06 Non-Critical
> L-07 Low
> L-08 Non-Critical
> L-09 Invalid
> L-10 Invalid
> L-11 Non-Critical
> L-12 Invalid
>
>
> The judge also highlighted the downgraded issues [#7](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/7) and [#8](https://github.com/code-423n4/2024-11-ethena-labs-findings/issues/8) to be linked in this report for completeness.

***

# Mitigation Review

Following the audit, [SpicyMeatball](https://code4rena.com/@spicymeatball) conducted a mitigation review of the Ethena team's mitigations. No new issues were identified during the review, and all mitigations were confirmed. 


| Reviewed Fix       | Description                                                                                                                                                    | Status             | 
|------------------------|------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| [L-04](https://github.com/ethena-labs/ethena-usdtb-contest/pull/1) | Missing re-entrancy Guard                                                                       | Mitigation Confirmed ✅ |
| [L-01](https://github.com/ethena-labs/ethena-usdtb-contest/pull/2) | The addBlacklistAddress and addWhitelistAddress functions do not check whether the user has opposite role | Mitigation Confirmed ✅ |
| [L-02](https://github.com/ethena-labs/ethena-usdtb-contest/pull/2) | In the constructor of UStbMinting contract, it does not set ustb                                          | Mitigation Confirmed ✅ |
| [L-08](https://github.com/ethena-labs/ethena-usdtb-contest/pull/2) |Unnecessary check of tokenConfig[asset].isActive in the _transferToBeneficiary function.                   | Mitigation Confirmed ✅ |
| [M-01](https://github.com/ethena-labs/ethena-usdtb-contest/pull/2)  | Blacklisted user can burn tokens during WHITELIST_ENABLED state                                  | Mitigation Confirmed ✅ |



# Disclosures

C4 is an open organization governed by participants in the community.

C4 audits incentivize the discovery of exploits, vulnerabilities, and bugs in smart contracts. Security researchers are rewarded at an increasing rate for finding higher-risk issues. Audit submissions are judged by a knowledgeable security researcher and solidity developer and disclosed to sponsoring developers. C4 does not conduct formal verification regarding the provided code but instead provides final verification.

C4 does not provide any guarantee or warranty regarding the security of this project. All smart contract software should be used at the sole risk and responsibility of users.
