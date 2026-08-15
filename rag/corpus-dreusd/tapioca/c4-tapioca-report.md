---
sponsor: "Tapioca DAO"
slug: "2024-02-tapioca"
date: "2024-05-23"
title: "Tapioca Invitational "
findings: "https://github.com/code-423n4/2024-02-tapioca-findings/issues"
contest: 333
---

# Overview

## About C4

Code4rena (C4) is an open organization consisting of security researchers, auditors, developers, and individuals with domain expertise in smart contracts.

A C4 audit is an event in which community participants, referred to as Wardens, review, audit, or analyze smart contract logic in exchange for a bounty provided by sponsoring projects.

During the audit outlined in this document, C4 conducted an analysis of the Tapioca smart contract system written in Solidity. The audit took place between February 26 — March 18, 2024.

## Wardens

In Code4rena's Invitational audits, the competition is limited to a small group of wardens; for this audit, 11 wardens contributed reports:

  1. [deadrxsezzz](https://code4rena.com/@deadrxsezzz)
  2. [GalloDaSballo](https://code4rena.com/@GalloDaSballo)
  3. [carrotsmuggler](https://code4rena.com/@carrotsmuggler)
  4. [KIntern\_NA](https://code4rena.com/@KIntern_NA) ([duc](https://code4rena.com/@duc) and [TrungOre](https://code4rena.com/@TrungOre))
  5. [rvierdiiev](https://code4rena.com/@rvierdiiev)
  6. [immeas](https://code4rena.com/@immeas)
  7. [cccz](https://code4rena.com/@cccz)
  8. [ladboy233](https://code4rena.com/@ladboy233)
  9. [ronnyx2017](https://code4rena.com/@ronnyx2017)
  10. [bin2chen](https://code4rena.com/@bin2chen)

This audit was judged by [LSDan](https://code4rena.com/@LSDan).

Final report assembled by [thebrittfactor](https://twitter.com/brittfactorC4).

# Summary

The C4 analysis yielded an aggregated total of 44 unique vulnerabilities. Of these vulnerabilities, 12 received a risk rating in the category of HIGH severity and 32 received a risk rating in the category of MEDIUM severity.

Additionally, C4 analysis included 10 reports detailing issues with a risk rating of LOW severity or non-critical. There was also 1 report recommending gas optimizations.

All of the issues presented here are linked back to their original finding.

# Scope

The code under review can be found within the [C4 Tapioca Repository](https://github.com/code-423n4/2024-02-tapioca), and is composed of 42 smart contracts written in the Solidity programming language and includes 4207 lines of Solidity code.

# Severity Criteria

C4 assesses the severity of disclosed vulnerabilities based on three primary risk categories: high, medium, and low/non-critical.

High-level considerations for vulnerabilities span the following key areas when conducting assessments:

- Malicious Input Handling
- Escalation of privileges
- Arithmetic
- Gas use

For more information regarding the severity criteria referenced throughout the submission review process, please refer to the documentation provided on [the C4 website](https://code4rena.com), specifically our section on [Severity Categorization](https://docs.code4rena.com/awarding/judging-criteria/severity-categorization).

# High Risk Findings (12)

## [[H-01] `MagnetarMintXChainModule.sol`:`mintBBLendXChainSGL` can be used to manipulate user positions by abusing whitelist privileges](https://github.com/code-423n4/2024-02-tapioca-findings/issues/185)
*Submitted by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/185), also found by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/124), [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/95), and cccz ([1](https://github.com/code-423n4/2024-02-tapioca-findings/issues/47), [2](https://github.com/code-423n4/2024-02-tapioca-findings/issues/24))*

The Magnetar functions use `_checkSender` function to check if the caller should be allowed to perform operations on the account. The function allows operations if the caller is the owner, or if the caller is a whitelisted trusted address.

```solidity
function _checkSender(address _from) internal view {
    if (_from != msg.sender && !cluster.isWhitelisted(0, msg.sender)) {
        revert Magnetar_NotAuthorized(msg.sender, _from);
    }
}
```

However, this means that if a malicious user is able to make a whitelisted contract call magnetar functions with their own payload, they can steal tokens and wreak havoc on other user's accounts!

The function `depositYBLendSGLLockXchainTOLP` in the `MagnetarAssetXChainModule` contract uses a similar check. This function deposits and lends into markets, for the account passed in as `data.user`. Crucially, it also extracts tokens from `data.user` for these operations. So if a malicious user was able to get this function called by a whitelisted contract and pass in a malicious `data.user`, they can cause the target user to lose tokens and manipulate their market positions. This is a high severity issue and the path to attack is demonstrated below.

### Proof of Concept

The entry point is the `MagnetarMintXChainModule` contract's `mintBBLendXChainSGL` function for the attacker. This is a special function, in the sense that this sets up the system for multiple cross chain calls. This function calls the `USDO` function which then does an lzcompose call on another chain to the Magnetar contract again. This is a complex function and the attacker can use this to manipulate the system.

The flow of control of this function is shown below:

```
  flowchart LR
      Caller --mintBBLendXChainSGL--> MA["Magnetar\n(chain A)"];
      MA -- sendPacket() --> USDOA["USDO\n(chain A)"];
      USDOA -- lzSend --> EA["Endpoint\n(chain A)"];
      EB["Endpoint\n(chain B)"] -- lzReceive (1) --> USDOB["USDO\n(chain B)"];
      USDOB -- sendCompose (2) --> EB;
      EB -- lzcompose (3) --> USDOB;
      USDOB --depositYBLendSGLLockXchainTOLP--> MB["Magnetar\n(chain B)"];
      MB --> Markets["Markets\n(chain B)"];
```

As shown in the above diagram, the caller initiates the call to the Magnetar contract. The Magnetar contract then does a cross-chain call via the `USDO` contract. It also sends along a lzcompose message which will be executed on chainB. On chainB, the `USDO` contract receives the call and initiates the lzcompose execution. Due to how the system is designed, this lzcompose message being executed by the `USDO` contract is actually a call to the Magnetar contract on chainB, specifically the `depositYBLendSGLLockXchainTOLP` function.

This can be shown by the fact that on chainA, the Magnetar encodes the lzcompose message into a struct.

```solidity
DepositAndSendForLockingData memory lendData = abi.decode(tapComposeMsg_, (DepositAndSendForLockingData));
lendData.lendAmount = data.mintData.mintAmount;
data.lendSendParams.lzParams.sendParam.composeMsg =
    TapiocaOmnichainEngineCodec.encodeToeComposeMsg(abi.encode(lendData), msgType_, msgIndex_, nextMsg_);
```

Then this same `DepositAndSendForLockingData` struct is accepted as an input on chainB `depositYBLendSGLLockXchainTOLP` function.

```solidity
function depositYBLendSGLLockXchainTOLP(DepositAndSendForLockingData memory data) public payable
```

On chainB, the `data.user` is the target of the operation. Since the caller is the `USDO` contract, which is not the `data.user` value, for this to work, the `USDO` contract must have been whitelisted by the system.

This means the malicious user can send in any `data.user` in their `data.lendSendParams.lzParams.sendParam.composeMsg` field, and the `USDO` contract will execute it on their behalf. No access checks will be performed, since the `USDO` contract is whitelisted. The target just needs to have given allowance to the Magnetar contract itself to perform market operations on their behalf. There are no checks on `DepositAndSendForLockingData.user` field in the `mintBBLendXChainSGL` function on chainA, so the malicious user can send in practically any address they want, and the whitelisted `USDO` contract will carry out the transaction.

This skips a crucial user check and manipulates other user positions; hence, it is a high severity issue.

### Recommended Mitigation Steps

The architecture of this crosschain call is quite vulnerable. Due to the whitelist, any function call that can be done via `USDO` contract is risky since it can override the Magnetar checks. The `mintBBLendXChainSGL` function on chainA should make sure the lzcompose `data.user` is the same as the current `data.user`, but this only blocks a single attack vector. `USDO` contract is crosschain compatible and allows lzcompose message, so any other methods which can be used to trigger such a cross chain call can abuse the whitelist.

**[0xRektora (Tapioca) confirmed via duplicate Issue #124](https://github.com/code-423n4/2024-02-tapioca-findings/issues/124#issuecomment-2016850994)**

**[cryptotechmaker (Tapioca) commented via duplicate Issue #124](https://github.com/code-423n4/2024-02-tapioca-findings/issues/124#issuecomment-2042730931):**
> PR [here](https://github.com/Tapioca-DAO/tapioca-periph/commit/3d38855c34bac2518bdf58e6a78b64b1c0e78438).

***

## [[H-02] Missing check on helper contract allows arbitrary actions and theft of assets](https://github.com/code-423n4/2024-02-tapioca-findings/issues/179)
*Submitted by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/179), also found by [ladboy233](https://github.com/code-423n4/2024-02-tapioca-findings/issues/12)*

The `MagnetarOptionModule` contract implements the `exitPositionAndRemoveCollateral` function which allows users to do a series of operations which is irrelevant to the issue. The user passes in the variable `data`, and later, `data.externalData` is used to extract out relevant contract addresses. These are then checked against a whitelist.

```solidity
if (data.externalData.bigBang != address(0)) {
    if (!cluster.isWhitelisted(0, data.externalData.bigBang)) {
        revert Magnetar_TargetNotWhitelisted(data.externalData.bigBang);
    }
}
if (data.externalData.singularity != address(0)) {
    if (!cluster.isWhitelisted(0, data.externalData.singularity)) {
        revert Magnetar_TargetNotWhitelisted(data.externalData.singularity);
    }
}
```

The main issue is that the `data.externalData` also has a `marketHelper` field which is not checked against a whitelist and ends up being used.

```solidity
(Module[] memory modules, bytes[] memory calls) = IMarketHelper(data.externalData.marketHelper).repay(
    address(this), data.user, false, data.removeAndRepayData.repayAmount
);
(bool[] memory successes, bytes[] memory results) = bigBang_.execute(modules, calls, true);
```

The helper contracts are used to construct the calldata for market operations. In the above snippet, the helper contract is passed in some data, and it is expected to create a calldata out of the passed in data. The expected output is the repay module and a `call` value which when executed, will repay for the `data.user`'s account.

However, since the `marketHelper` contract is never checked against a whitelist, malicious user can pass in any address in that place. So the above call can return any data payload, and the `bigBang_.execute` will execute it without any checks. This means the malicious helper contract can return a `borrow` payload of some random user, and the contract will end up borrowing USDO against that user's position. The Magnetar contract is assumed to have approval for market operations, and thus the Magnetar's approval is essentially exploited by the attacker to perform arbitrary actions on any user's account.

This can be used by any user to steal collateral from other user's bigbang position, or borrow out usdo tokens on their position. Since this is direct theft, this is a high severity issue.

### Proof of Concept

The absence of checks is evident from the code snippet. Assuming `marketHelper` contract is malicious, we see that is used in 2 places to create payloads, which must also be deemed malicious.

```solidity
(Module[] memory modules, bytes[] memory calls) = IMarketHelper(data.externalData.marketHelper).repay(
    address(this), data.user, false, data.removeAndRepayData.repayAmount
);
```

```solidity
(Module[] memory modules, bytes[] memory calls) = IMarketHelper(data.externalData.marketHelper)
    .removeCollateral(data.user, removeCollateralTo, collateralShare);
```

These are then executed, and the Magnetar is assumed to have approvals from users, so these are obviously malicious interactions.

In the other module contracts, the `marketHelper` is checked against a whitelist, but not in this module. This is a clear oversight. Below is the example from the `MagnetarMintCommonModule`:

```solidity
if (!cluster.isWhitelisted(0, marketHelper)) {
    revert Magnetar_TargetNotWhitelisted(marketHelper);
}
```

### Recommended Mitigation Steps

Check the helper contract against a whitelist.

**[cryptotechmaker (Tapioca) disagreed with severity and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/179#issuecomment-2009630642):**
 > Low/Invalid; even if the market helper is not checked (and I agree it's ok to add that verification) the module which is going to be executed is checked on the BB/SGL side and the action that's being performed also checks the allowances

**[ladboy233 (warden) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/179#issuecomment-2046304018):**
> I think the severity is not inflated and the severity is high and the issue clearly leads to theft of fund.
> 
> 1. Magnatar is a like a router contract and help user compose multicall.
> 2. User calls magnetar function -> [delegate calls Option Module](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/Magnetar.sol#L143).
> 
> ```solidity
>  /// @dev Modules will not return result data.
>             if (_action.id == MagnetarAction.OptionModule) {
>                 _executeModule(MagnetarModule.OptionModule, _action.call);
>                 continue; // skip the rest of the loop
>             }
> ```
> 
> 3. User needs to give a lot of approve for magnetar contract to allow magnetar contract pull fund out of user's account to complete transaction.
> 
> 4. To prevent abuse of allowance, this check is [made in-place](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarOptionModule.sol#L60).
> 
> ```solidity
>    function exitPositionAndRemoveCollateral(ExitPositionAndRemoveCollateralData memory data) public payable {
>         // Check sender
>         _checkSender(data.user);
> ```
> 
> Which calls:
> 
> ```solidity
>  function _checkSender(address _from) internal view {
>         if (_from != msg.sender && !cluster.isWhitelisted(0, msg.sender)) {
>             revert Magnetar_NotAuthorized(msg.sender, _from);
>         }
>     }
> ```
> 
> The from `!= msg.sender` is super important, otherwise.
> 
> If user A gives allowance to magnetar contract, user B can set `data.user` to user A and steal fund from user A directly.
> 
> 5. Lack of validation of market helper allows malicious actor executes arbitrary multicall. See [here](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarOptionModule.sol#L173).
> 
> ```solidity
>  (Module[] memory modules, bytes[] memory calls) = IMarketHelper(data.externalData.marketHelper).repay(
>                 address(this), data.user, false, data.removeAndRepayData.repayAmount
>             );
>             (bool[] memory successes, bytes[] memory results) = bigBang_.execute(modules, calls, true);
> ```
> 
> As for sponsor comments:
> 
> > The module which is going to be executed is checked on the BB/SGL side and the action that's being performed also checks the allowances.
> 
> This is the code in BBCollateral module:
> 
> `bigBang_.execute` multicall to `bigBang` module and one of the module is BBCollateral module:
> 
> ```
>    function removeCollateral(address from, address to, uint256 share)
>         external
>         optionNotPaused(PauseType.RemoveCollateral)
>         solvent(from, false)
>         notSelf(to)
>         allowedBorrow(from, share)
>     {
>         _removeCollateral(from, to, share);
>     }
> ```
> 
> The validation that sponsor mentions is in the modifier:
> 
> ```solidity
>  allowedBorrow(from, share)
> ```
> 
> Which calls:
> 
> ```solidity
>   function _allowedBorrow(address from, uint256 share) internal virtual override {
>         if (from != msg.sender) {
>             // TODO review risk of using this
>             (uint256 pearlmitAllowed,) = penrose.pearlmit().allowance(from, msg.sender, address(yieldBox), collateralId);
>             require(allowanceBorrow[from][msg.sender] >= share || pearlmitAllowed >= share, "Market: not approved");
>             if (allowanceBorrow[from][msg.sender] != type(uint256).max) {
>                 allowanceBorrow[from][msg.sender] -= share;
>             }
>         }
>     }
> ```
> 
> Obviously "from" is not `msg.sender`, but `msg.sender` is the magnetar contract that hold user's allowance.
> 
> 6. Protocol fix the lack of market helper validation in the other part of the codebase, see [here](https://github.com/Tapioca-DAO/TapiocaZ/pull/180/files). The exact same issue should be fixed in Option module as well.
> 
> 7. Other way to abuse pending allowance is marked as high severity [here](https://github.com/code-423n4/2024-02-tapioca-findings/issues/100).
> 
> 8. Abuse this issue is not fixed [here](https://hacken.io/discover/sushi-hack-explained/).
> 
> This type of exploit can occur:
> 
> 1. User approves spending allowance to sushi router.
> 2. Funds sit idle in users wallet.
> 3. Attacker triggers `transferFrom` from victim address to hacker address -> exploit.
> 
> In this case:
> 
> 1. User approves spending allowance to magnetar.
> 2. Funds sit idle in users wallet.
> 3. Attacker bypasses the `_checkSender` and constructs multicall to remove collateral from user's account directly.

**[carrotsmuggler (warden) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/179#issuecomment-2047008870):**
 > This should be valid. According to the sponsor, `even if the market helper is not checked the module which is going to be executed is checked on the BB/SGL side`. 
> 
> This is true. However the bigbang/sgl markets do the check on `msg.sender`, which is the magnetar contract itself, which is expected to have allowance from the users. Checks are not done on the initiator of this transaction. This is highlighted [here](https://github.com/Tapioca-DAO/Tapioca-bar/blob/b1a30b07ec1fd2626a0256f0393edac1e5055ebd/contracts/markets/Market.sol#L419-L430) and below.
> 
> ```solidity
> function _allowedBorrow(address from, uint256 share) internal virtual override {
>         if (from != msg.sender) {
>             if (share == 0) revert AllowanceNotValid();
> 
>             // TODO review risk of using this
>             (uint256 pearlmitAllowed,) = penrose.pearlmit().allowance(from, msg.sender, address(yieldBox), collateralId);
>             require(allowanceBorrow[from][msg.sender] >= share || pearlmitAllowed >= share, "Market: not approved");
>             if (allowanceBorrow[from][msg.sender] != type(uint256).max) {
>                 allowanceBorrow[from][msg.sender] -= share;
>             }
>         }
>     }
> ```
> 
> Magnetar is a privileged contract, and this function allows other users to abuse this privilege. This is basically approval hijacking, and so is high severity.

**[0xRektora (Tapioca) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/179#issuecomment-2051922427):**
 > @LSDan, this can be approved as a high risk.
> 
> While we switched the model to use "atomic" approvals using Pearlmit, it's better to be safe than sorry. The reviewed code also still has an obsolete `allowanceBorrow` which could help initiate this attack.

**[0xWeiss (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/179#issuecomment-2125586073)**

***

## [[H-03] Absence of restrictions on the sender of the `twTAP.claimsReward()` function could enable attackers to freeze reward tokens within the Tap token contract](https://github.com/code-423n4/2024-02-tapioca-findings/issues/142)
*Submitted by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/142), also found by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/145), [immeas](https://github.com/code-423n4/2024-02-tapioca-findings/issues/171), [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/120), [ronnyx2017](https://github.com/code-423n4/2024-02-tapioca-findings/issues/96), GalloDaSballo ([1](https://github.com/code-423n4/2024-02-tapioca-findings/issues/86), [2](https://github.com/code-423n4/2024-02-tapioca-findings/issues/72), [3](https://github.com/code-423n4/2024-02-tapioca-findings/issues/57)), [cccz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/22), and [ladboy233](https://github.com/code-423n4/2024-02-tapioca-findings/issues/3)*

<https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/governance/twTAP.sol#L396-L404> 

The function `twTAP.claimRewards()` is utilized to claim the reward distributed to the position identified by `_tokenId`.

```solidity
function claimRewards(uint256 _tokenId, address _to)
    external
    nonReentrant
    whenNotPaused
    returns (uint256[] memory amounts_)
{
    _requireClaimPermission(_to, _tokenId);
    amounts_ = _claimRewards(_tokenId, _to);
}
```

This function can be triggered by anyone, provided that the receiver of the claimed reward `_to` is either the owner of the position or an address approved by the position's owner.

In the function `TapTokenReceiver._claimTwpTapRewardsReceiver()`, the `twTAP.claimRewards()` function is invoked at [line 156](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/tokens/TapTokenReceiver.sol#L156) to calculate the reward assigned to `_tokenId` and claim the reward to this contract before transferring it to the receiver on another chain. To achieve this, the position's owner must first approve this contract to access the position before executing the function.

```solidity
function _claimTwpTapRewardsReceiver(bytes memory _data) internal virtual twTapExists {
    ClaimTwTapRewardsMsg memory claimTwTapRewardsMsg_ = TapTokenCodec.decodeClaimTwTapRewardsMsg(_data);
    uint256[] memory claimedAmount_ = twTap.claimRewards(claimTwTapRewardsMsg_.tokenId, address(this));

    ...
}
```

However, between the call to grant approval to the contract and the execution of the `_claimTwpTapRewardsReceiver()` function, an attacker can insert a transaction calling `twTAP.claimRewards(_tokenId, TapTokenReceiver)`. By doing so, the rewards will be claimed to the `TapTokenReceiver` contract before the `_claimTwpTapRewardsReceiver()` function is invoked. Consequently, the return value of `claimedAmount_ = twTap.claimRewards(claimTwTapRewardsMsg_.tokenId, address(this))` within the function will be `0` for all elements, resulting in no rewards being claimed for the receiver. As a result, the reward tokens will become trapped in the contract.

In the event that the sender utilizes multiple LayerZero composed messages containing two messages:

- Permit message: to approve permission of `_tokenId` to the `TapTokenReceiver` contract.
- Claim reward message: to trigger the `_claimTwpTapRewardsReceiver()` function and claim the reward.

The attacker cannot insert any `twTAP.claimRewards()` between these two messages, as they are executed within the same transaction on the destination chain. However, the permit message can be triggered by anyone, not just the contract `TapTokenReceiver`. The attacker can thus trigger the permit message on the destination chain and subsequently call the `twTAP.claimRewards()` function before the `_claimTwpTapRewardsReceiver()` message is delivered on the destination chain.

### Impact

The reward tokens will become trapped within the `TapTokenReceiver` contract.

### Recommended Mitigation Steps

Consider updating the function `twTAP.claimRewards()` as depicted below to impose restrictions on who can invoke this function:

```solidity
function claimRewards(uint256 _tokenId, address _to)
    external
    nonReentrant
    whenNotPaused
    returns (uint256[] memory amounts_)
{
    _requireClaimPermission(msg.sender, _tokenId);
    _requireClaimPermission(_to, _tokenId);
    amounts_ = _claimRewards(_tokenId, _to);
}
```

**[0xRektora (Tapioca) confirmed via duplicate Issue #120](https://github.com/code-423n4/2024-02-tapioca-findings/issues/120#issuecomment-2016850113)**

**[0xRektora (Tapioca) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/142#issuecomment-2054134428):**
 > Just as reference, the proposed mitigation will not work, because in this context `msg.sender == _to`.

***

## [[H-04] Incorrect approval mechanism breaks all Magnetar functionality](https://github.com/code-423n4/2024-02-tapioca-findings/issues/125)
*Submitted by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/125), also found by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/160)*

The Magnetar contract hands out approvals to various contracts so that the target contracts can use any tokens held currently by the Magnetar contract.

The issue is that at some point of time, all the target contracts were refactored to use `permitC` to handle token transfers. However, this change wasn't reflected in the Magnetar contracts. Thus, instead of handing out `permitC` approvals, Magnetar hands out normal ERC20 approvals or yieldbox approvals. This essentially breaks the whole system.

There are numerous instances of this in the codebase. Essentially, almost every approval in the Magnetar contract is incorrect. Below are some examples, however the entire codebase needs to be checked for approvals and corrected.

The `_depositYBLendSGL` function in `MagnetarAssetCommonModule.sol` contract gives approval to the singularity contract via yieldbox. However, if we check the `_addTokens` function in the singularity contract below, we see the token transfers actually take place via `pearlmit`/`permitC`.

```solidity
_setApprovalForYieldBox(singularityAddress, yieldBox_);
```

<https://github.com/Tapioca-DAO/Tapioca-bar/blob/9d76b2fc7e2752ca8a816af2d748a0259af5ea42/contracts/markets/singularity/SGLCommon.sol#L165-L177>

Since the Magnetar contract does not give `permitC` approval to the singularity contract, and instead only gives yieldbox approval, the singularity contract is unable to transfer tokens from the Magnetar contract.

Similarly, in the `_wrapSglReceipt` function, the Magnetar gives approval to the TOFT contract vie ERC20 approval:

```solidity
IERC20(sgl).approve(tReceiptAddress, fraction);
```

But if we check the TOFT contract, we see the tokens are transferred via `permitC` and not with the raw tokens:

<https://github.com/Tapioca-DAO/TapiocaZ/blob/57750b7e997e5a1654651af9b413bbd5ea508f59/contracts/tOFT/BaseTOFT.sol#L73>

Since the Magnetar contract does not hand out the `permitC` approvals, most of the token transfers via Magnetar will fail.

### Proof of Concept

The issue arises due to the target contracts using `permitC`, while Magnetar only giving approvals of the token itself or yieldbox. This can be verified by checking the Magnetar contract and the target contracts, as shown above.

### Recommended Mitigation Steps

Refactor Magnetar to give approvals via `permitC` throughout.

**[cryptotechmaker (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/125#issuecomment-2011767366)**

***

## [[H-05] `_vested()` claimable amount calculation error](https://github.com/code-423n4/2024-02-tapioca-findings/issues/111)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/111), also found by [bin2chen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/112), [immeas](https://github.com/code-423n4/2024-02-tapioca-findings/issues/167), [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/150), [ronnyx2017](https://github.com/code-423n4/2024-02-tapioca-findings/issues/99), and [deadrxsezzz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/37)*

The `Vesting._vested()` method is used to calculate the maximum claimable amount for the current user. The calculation formula is as follows: `(_totalAmount * (block.timestamp - _start)) / _duration`. If there is an `__initialUnlockTimeOffset`, it needs to be subtracted from `_start` before performing the calculation, i.e., `_start = _start - __initialUnlockTimeOffset`.

```solidity
    function _vested(uint256 _totalAmount) internal view returns (uint256) {
        uint256 _cliff = cliff;
        uint256 _start = start;
        uint256 _duration = duration;

        if (_start == 0) return 0; // Not started

        if (_cliff > 0) {
            _start = _start + _cliff; // Apply cliff offset
            if (block.timestamp < _start) return 0; // Cliff not reached
        }

@>      if (block.timestamp >= _start + _duration) return _totalAmount; // Fully vested

        _start = _start - __initialUnlockTimeOffset; // Offset initial unlock so it's claimable immediately
        return (_totalAmount * (block.timestamp - _start)) / _duration; // Partially vested
    }
```

The issue with the code snippet above is that the check for being "Fully vested" is incorrect; it does not take into account the `__initialUnlockTimeOffset`. The correct approach should be:
`if (block.timestamp >= _start - __initialUnlockTimeOffset + _duration) return _totalAmount;// Fully vested`. Resulting in calculations that may be greater than the maximum number `_totalAmount`

Example:
`_totalAmount  =  500 ,  duration = 1000 __initialUnlockTimeOffset = 100 start = 1000  block.timestamp= 1999` because `block.timestamp < start + duration`  (`1999 < 1000 + 1000`) it will not return `Fully vested`.

Final calculation result:
start = `start - __initialUnlockTimeOffset = 1000 - 100 = 900`.
return = `(_totalAmount * (block.timestamp - _start)) / _duration = 500 * (1999 - 900) / 1000 = 549.5`.

It is greater 49.5 than the maximum `_totalAmount=500`.

### Impact

Users can `claim' more than they should.

### Recommended Mitigation

```diff
    function _vested(uint256 _totalAmount) internal view returns (uint256) {
        uint256 _cliff = cliff;
        uint256 _start = start;
        uint256 _duration = duration;

        if (_start == 0) return 0; // Not started

        if (_cliff > 0) {
            _start = _start + _cliff; // Apply cliff offset
            if (block.timestamp < _start) return 0; // Cliff not reached
        }

-       if (block.timestamp >= _start + _duration) return _totalAmount; // Fully vested
+       if (block.timestamp >= _start -  __initialUnlockTimeOffset + _duration) return _totalAmount; // Fully vested

        _start = _start - __initialUnlockTimeOffset; // Offset initial unlock so it's claimable immediately
        return (_totalAmount * (block.timestamp - _start)) / _duration; // Partially vested
    }
```
**[cryptotechmaker (Tapioca) confirmed, but disagreed with severity and commented via duplicate Issue #167](https://github.com/code-423n4/2024-02-tapioca-findings/issues/167#issuecomment-2034003168)**
> PR [here](https://github.com/Tapioca-DAO/tap-token/pull/175).

***

## [[H-06] Attacker can use `MagnetarAction.OFT` action of the Magnet to perform operations as any user including directly stealing user tokens](https://github.com/code-423n4/2024-02-tapioca-findings/issues/100)
*Submitted by [ronnyx2017](https://github.com/code-423n4/2024-02-tapioca-findings/issues/100), also found by [immeas](https://github.com/code-423n4/2024-02-tapioca-findings/issues/170), carrotsmuggler ([1](https://github.com/code-423n4/2024-02-tapioca-findings/issues/122), [2](https://github.com/code-423n4/2024-02-tapioca-findings/issues/121)), GalloDaSballo ([1](https://github.com/code-423n4/2024-02-tapioca-findings/issues/80), [2](https://github.com/code-423n4/2024-02-tapioca-findings/issues/79), [3](https://github.com/code-423n4/2024-02-tapioca-findings/issues/78)), [rvierdiiev](https://github.com/code-423n4/2024-02-tapioca-findings/issues/63), [deadrxsezzz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/46), [cccz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/23), and [ladboy233](https://github.com/code-423n4/2024-02-tapioca-findings/issues/7)*

<https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/Magnetar.sol#L153-L156> 

<https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/Magnetar.sol#L325-L333> 

<https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/MagnetarStorage.sol#L93-L97>

This issue requires the combination of two vulnerabilities to achieve the impact described in the title. The first vulnerability is that the `Magnetar._processOFTOperation` function doesn't check the function sigs in the action calldata with the the target addresses. It only ensures the calling target addresses are in the Whitelist of the Cluster. So an attacker can use this vuln to call any whitelist target address from the Magnetar.

The second vulnerability is that the Magnetar contract address itself will also be added to the Cluster whitelist. It can be found in the following integration test [here](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/test_hardhat/magnetar.test.ts#L389). If the attacker can let the Magnetar call itself, the `msg.sender` in the sub-call will be in the whitelist. It will bypass the `_checkSender` check:

```solidity
    function _checkSender(address _from) internal view {
        if (_from != msg.sender && !cluster.isWhitelisted(0, msg.sender)) {
            revert Magnetar_NotAuthorized(msg.sender, _from);
        }
    }
```

### Impact

Combining the two issues mentioned above, we can carry out the following exploitation.

1. Call `Magnetar.burst` function with `_action.id == MagnetarAction.OFT`, which will call `_processOFTOperation` function. The `_target` is the Magnetar contract itself, and the `_actionCalldata` is still an encoded calldata to call the `Magnetar.burst` function with `_action.id == MagnetarAction.OFT` again.
2. In the second call, the `msg.sender` will be the Magnetar itself, so the from address check in the `_checkSender` function will be skipped directly because the `msg.sender` is in the whitelist.
3. Now the attacker can pretend to be anyone and call any contract through the Magnetar. Please note that users approved their tokens to Magnetar if they used it.

### Proof of Concept

Taking `MagnetarAssetModule` as an example, it demonstrates how an attacker could steal users' collateral in the market.

Firstly the `_checkSender(data.user);` can be bypassed directly.

And make `data.withdrawCollateralParams.withdraw = true`, so the `collateralWithdrawReceiver` will be the Magnetar contract itself:

    address collateralWithdrawReceiver = data.withdrawCollateralParams.withdraw ? address(this) : data.user;

Then if `collateralShare > 0`, the function will call `_withdrawToChain(data.withdrawCollateralParams);` to withdraw the collateral to the another chain by sending LZ message.

There is no check for `withdrawCollateralParams` in the `_withdrawToChain` function. The attacker can set the receiver address to his address and finally receive the tokens on the target chain.

### Recommendation

Check the target function sig in the `_processOFTOperation` function.

**[cryptotechmaker (Tapioca) confirmed, but disagreed with severity and commented via duplicate Issue #170](https://github.com/code-423n4/2024-02-tapioca-findings/issues/170#issuecomment-2009731108):**
>Medium, the same happens if you approve the attacker for an ERC20. However, this is worth fixing in my opinion. I think we can add specific selectors instead of allowing any call to be executed.
>
>Fixed [here](https://github.com/Tapioca-DAO/tapioca-periph/commit/d4bb69d70f57d570a9608b797f1effc35cfa8490).

***

## [[H-07] Incorrect math means `data.removeAndRepayData.removeAssetFromSGL` will never work once SGL has accrued interest](https://github.com/code-423n4/2024-02-tapioca-findings/issues/91)
*Submitted by [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/91), also found by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/159) and [bin2chen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/113)*

The code to remove shares from Singularity is as follows:

<https://github.com/Tapioca-DAO/tapioca-periph/blob/2ddbcb1cde03b548e13421b2dba66435d2ac8eb5/contracts/Magnetar/modules/MagnetarOptionModule.sol#L158-L159>

```solidity
            singularity_.removeAsset(data.user, removeAssetTo, share);
```

Where `share` is computed in this way:

<https://github.com/Tapioca-DAO/tapioca-periph/blob/2ddbcb1cde03b548e13421b2dba66435d2ac8eb5/contracts/Magnetar/modules/MagnetarOptionModule.sol#L153>

```solidity
uint256 share = yieldBox_.toShare(_assetId, _removeAmount, false);
```

The line is calculating: The (incorrectly rounded down) amount of shares of Yieldbox to burn in order to withdraw from Yieldbox the `_removeAmount`.

But the code is calling:

`singularity_.removeAsset(data.user, removeAssetTo, share);`

This is asking Singularity to remove a % (part) of the total assets in Singularity. Due to this, the line will stop working as soon as singularity has had any operation that generated interest.

### Proof of Concept

Please see the formula used by Singularity for pricing asset:

<https://github.com/Tapioca-DAO/Tapioca-bar/blob/c2031ac2e2667ac8f9ac48eaedae3dd52abef559/contracts/markets/singularity/SGLCommon.sol#L199-L216>

```solidity
    function _removeAsset(address from, address to, uint256 fraction) internal returns (uint256 share) {
        if (totalAsset.base == 0) {
            return 0;
        }
        Rebase memory _totalAsset = totalAsset;
        uint256 allShare = _totalAsset.elastic + yieldBox.toShare(assetId, totalBorrow.elastic, false);
        share = (fraction * allShare) / _totalAsset.base;
    }
```

As you can see, the `fraction` will be computed against `_totalAsset.elastic + yieldBox.toShare(assetId, totalBorrow.elastic, false);`. Meaning that the math will be incorrect as soon as any operation is done in Singularity

### Coded POC

This Poc is built on the public repo: <https://github.com/GalloDaSballo/yieldbox-foundry>

We show how a change in interest will change `fraction`. In my local testing, `fraction` and `shares` are already out of sync. However, due to decimals it may be possible for them to be the same value, until some interest will make `borrowElastic` grow.

### Logs

```
[PASS] testSingularityRebasedMathIsNotYieldbox() (gas: 34810)
Logs:
fraction 999999990000000099999
share 100000000000000000000000000000

[PASS] testSingularityRebasedMathIsNotYieldboxAfterInterest() (gas: 34756)
Logs:
fraction 666666662222222251851
share 100000000000000000000000000000
```

### Code

```solidity

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {TargetFunctions} from "./TargetFunctions.sol";
import {FoundryAsserts} from "@chimera/FoundryAsserts.sol";

contract CryticToFoundry is Test, TargetFunctions, FoundryAsserts {
    function setUp() public {
        setup();
    }

    
    function testSingularityRebasedMathIsNotYieldbox() public {        
        uint256 amountToRepay = 1000e18;

        uint256 totalAssetShares = 2000e18;
        uint256 totalAssetBase = 2000e18;
        uint256 totalBorrowElastic = 2000e18;

        uint256 share = yieldBox.toShare(assetId, amountToRepay, false);
        uint256 allShare = totalAssetShares + yieldBox.toShare(assetId, totalBorrowElastic, true);

        uint256 fraction = allShare == 0 ? share : (share * totalAssetBase) / allShare;
        console2.log("fraction", fraction);
        console2.log("share", share);
    }

    function testSingularityRebasedMathIsNotYieldboxAfterInterest() public {        
        uint256 amountToRepay = 1000e18;

        uint256 totalAssetShares = 2000e18;
        uint256 totalAssetBase = 2000e18;
        uint256 totalBorrowElastic = 3000e18; // NOTE: Higher cause of interest

        uint256 share = yieldBox.toShare(assetId, amountToRepay, false);
        uint256 allShare = totalAssetShares + yieldBox.toShare(assetId, totalBorrowElastic, true);

        uint256 fraction = allShare == 0 ? share : (share * totalAssetBase) / allShare;
        console2.log("fraction", fraction);
        console2.log("share", share);
    }
}
```

### Mitigation

The unused function `getFractionForAmount` should help, minus some possible rounding considerations.

**[cryptotechmaker (Tapioca) confirmed, but disagreed with severity and commented via duplicate Issue #159](https://github.com/code-423n4/2024-02-tapioca-findings/issues/159#issuecomment-2034483179):**
> PR [here](https://github.com/Tapioca-DAO/tapioca-periph/commit/a22fdf0efe5a63538e072f4947ed65fd72e029a2).

***

## [[H-08] `IMarket.execute.selector`, `_checkSender` bypass allows to execute arbitrary operations](https://github.com/code-423n4/2024-02-tapioca-findings/issues/77)
*Submitted by [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/77)*

Because of an incorrect interpretation of `calldata` for the `execute` signature, we are able to bypass the `_checkSender` and perform arbitrary `execute` operations as Magnetar.

### Impact

`Market.execute` uses the following signature:

```solidity
    function execute(Module[] calldata modules, bytes[] calldata calls, bool revertOnFail)
```

For Calldata variables, the size `4:36` is going to be the `length` of the `calldata`. We can specify an arbitrary length that matches the value of any address that is whitelisted, or any address that we're able to generate. This will allow us to bypass the check and perform arbitrary execution in the market.

After forging our length, we have bypassed the check, allowing us to execute, while having permissions/allowances from other users:

<https://github.com/Tapioca-DAO/tapioca-periph/blob/2ddbcb1cde03b548e13421b2dba66435d2ac8eb5/contracts/Magnetar/Magnetar.sol#L256-L281>

```solidity

    function _processMarketOperation(
        address _target,
        bytes calldata _actionCalldata,
        uint256 _actionValue,
        bool _allowFailure
    ) private {
        if (!cluster.isWhitelisted(0, _target)) revert Magnetar_NotAuthorized(_target, _target);

        /// @dev owner address should always be first param.
        // addCollateral(address from,...)
        // borrow(address from,...)
        // addAsset(address from,...)
        // repay(address _from,...)
        // buyCollateral(address from,...)
        // sellCollateral(address from,...)
        bytes4 funcSig = bytes4(_actionCalldata[:4]);
        if (
            funcSig == IMarket.execute.selector || funcSig == ISingularity.addAsset.selector /// @audit ??????
                || funcSig == ISingularity.removeAsset.selector
        ) {
            /// @dev Owner param check. See Warning above.
            _checkSender(abi.decode(_actionCalldata[4:36], (address))); /// @audit we can forge this 80%
            _executeCall(_target, _actionCalldata, _actionValue, _allowFailure);
            return;
        }
```

### POC

This will allow us to transfer any token that is approved to us, stealing them. We can proceed to mine an address with low enough zeros, or simply use a suitable system address for any chain, as the requirement for `_checkSender(abi.decode(_actionCalldata[4:36], (address)))` is simply to match the `msg.sender`.

An example would be the Optimism Portal on L2 which would have very low address; meaning we would be able to have a sufficient amount of operations there. Once we can bypass the check, we will be able to have Magnetar `execute` any market operation, such as transfers of other people tokens, allowing us to steal them.

### Coded POC

The Coded POC shows how we can forge calldata to bypass the check, as long as we can use an address that matches the abi.decoding of the length:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

contract MockCallerChecker {

  function doTheCheck(bytes calldata _actionCalldata) external {
    console2.log("Calldata Length", _actionCalldata.length);
    _checkSender(abi.decode(_actionCalldata[4:36], (address)));
  }

  function _checkSender(address entry) internal {
    console2.log("msg.sender", msg.sender);
    console2.log("entry", entry);
    require(msg.sender == entry);
  }
}


contract BasicTest is Test {
    // 4 bytes is funsig 0xaaaaaaaa
    // 32 bytes are the address (since abi.encoding uses a full word)
    // 0000000000000000000000000000000000000000111111111111111111111111
    bytes data = hex"aaaaaaaa0000000000000000000000000000000000000000111111111111111111111111";

    function testDemo() public {
      MockCallerChecker checker = new MockCallerChecker();
      console2.log(data.length);

      // Same address as the length
      vm.prank(address(0x111111111111111111111111));
      checker.doTheCheck(data);

      // For a real exploit, all we have to do is find the cheapest between available addresses and one we can mine
    }
}
```

### Logs

```solidity
Logs:
  36
  Calldata Length 36
  msg.sender 0x0000000000000000111111111111111111111111
  entry 0x0000000000000000111111111111111111111111

Traces:
  [217996] BasicTest::testDemo()
    ├─ [169614] → new MockCallerChecker@0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
    │   └─ ← 847 bytes of code
    ├─ [0] console::log(36) [staticcall]
    │   └─ ← ()
    ├─ [0] VM::prank(0x0000000000000000111111111111111111111111)
    │   └─ ← ()
    ├─ [2931] MockCallerChecker::doTheCheck(0xaaaaaaaa0000000000000000000000000000000000000000111111111111111111111111)
    │   ├─ [0] console::log("Calldata Length", 36) [staticcall]
    │   │   └─ ← ()
    │   ├─ [0] console::log("msg.sender", 0x0000000000000000111111111111111111111111) [staticcall]
    │   │   └─ ← ()
    │   ├─ [0] console::log("entry", 0x0000000000000000111111111111111111111111) [staticcall]
    │   │   └─ ← ()
    │   └─ ← ()
    └─ ← ()
```

### Notes on Cost

The cost of the attack is the cost of finding an address that is small enough to steal all funds; As far as I can tell, this would take a few days on specialized hardware.

On certain chains, with system contracts (e.g. Optimism) the cost would be zero as we could act on behalf of the Portal and we would be able to use very small amount of data. 

It's also worth noting that Arbitrum (the base chain of the project), has no gas limit on blocks.

### Mitigation

It may be necessary to remove `execute` from available commands as all commands will be performed by `Magnetar`.

### Assessed type

en/de-code

**[0xWeiss (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/77#issuecomment-2125590110)**

***

## [[H-09] Funds can be stolen through remote transfer functionality](https://github.com/code-423n4/2024-02-tapioca-findings/issues/76)
*Submitted by [rvierdiiev](https://github.com/code-423n4/2024-02-tapioca-findings/issues/76)*

User can send LZ message through any `Oft` token using the `TapiocaOmnichainSender.sendPacket `function. User provides params that should be used and also provides [composed message](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainSender.sol#L57C75-L57C86) if he needs to send it.

What is important for composed message is [during crafting message](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/BaseTapiocaOmnichainEngine.sol#L166-L172), `msg.sender` is stored as `srcChainSender_`. In this way we know who have triggered composed call.

```solidity
function encode(
        bytes32 _sendTo,
        uint64 _amountShared,
        bytes memory _composeMsg
    ) internal view returns (bytes memory _msg, bool hasCompose) {
        hasCompose = _composeMsg.length > 0;
        // @dev Remote chains will want to know the composed function caller ie. msg.sender on the src.
        _msg = hasCompose
            ? abi.encodePacked(_sendTo, _amountShared, addressToBytes32(msg.sender), _composeMsg)
            : abi.encodePacked(_sendTo, _amountShared);
    }
```

The amount that should be sent to other chain is burnt (if any) and LZ call [is sent](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainSender.sol#L73-L74). On another chain, the call will be handled [by `TapiocaOmnichainReceiver._lzReceive` function](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L72C14-L72C24). This function [will mint tokens to recipient](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L85). If the composed message was included, then it will [sent it to endpoint](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L93-L98), so it can be triggered later.

When composed message is triggered, then [`lzCompose` function](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L120C14-L120C23) handles it. As you can see, the function retrieves `srcChainSender_` to know who was initiator of compose call on source chain. Then [`_lzCompose` function](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L139) continue processing of message.

Using [`msgType`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L148C17-L148C25) user can provide operation he wants to execute on target chain. One of operations [is `MSG_REMOTE_TRANSFER`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L154) that allows to remotely send tokens to another chain. The flow is next: on chain A user initiates compose call to chain B, that will send his tokens on chain B to chain A, or will use allowance to send tokens of other user on chain B to chain A. Let's check how it works.

First, the function should [transfer tokens from owner to `address(this)`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L218-L220). This function receives owner of funds and `_srcChainSender` as inputs [to check allowance](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L287-L289). As you can see, in the case of if `_srcChainSender` is owner then we don't need any approve.

After transfer is done to `address(this)` then the [contract can send them back to chain A](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L223C9-L225). So the function [burns tokens](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L250) and crafts message to another chain and it can have composed call again; which means that [it will include `_srcChainSender`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L266C96-L266C111), so the contract on chain A knows who initiated the call.

The problem is that `_srcChainSender` that will be included is [owner of funds on chain B](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L224C13-L224C37), which is incorrect.

Here's the described attack flow:

1. Victim has funds on chain A, that attacker is going to steal to chain B.
2. Attacker on chain A initiates compose call with victim as owner of funds and provides amount `0` as amount to transfer of chain B.
3. Compose call succeed on chain B as it is possible to transfer `0` tokens and then another compose message was included, which transfers all tokens from victim to attacker on chain B.
4. Because `_srcChainSender` was set to victim on first compose call. Then the next compose call on chain A will think that victim is initiator of remote transfer, which means that no allowance will be checked.
5. Funds are stolen to attacker address on chain B.

### Impact

Possible to steal funds.

### Tools Used

VsCode

### Recommended Mitigation Steps

Provide `_srcChainSender` as initiator of compose call.

    _internalRemoteTransferSendPacket(
                _srcChainSender, remoteTransferMsg_.lzSendParam, remoteTransferMsg_.composeMsg
            );

### Assessed type

Error

**[0xWeiss (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/76#issuecomment-2125592960)**

***

## [[H-10] Adversary can steal approved `tOLP`s to Magnetar via `_paricipateOnTOLP`](https://github.com/code-423n4/2024-02-tapioca-findings/issues/54)
*Submitted by [deadrxsezzz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/54)*

Any user could steal any approved `tOLP` to Magnetar. This is because within the Magnetar call, if the user has not minted a `tOLP` NFT, they can participate with any id they wish, by inputting it in `participateData`.

```solidity
    function _participateOnTOLP(
        IOptionsParticipateData memory participateData,
        address user,
        address lockDataTarget,
        uint256 tOLPTokenId
    ) internal {
        if (!cluster.isWhitelisted(0, participateData.target)) {
            revert Magnetar_TargetNotWhitelisted(participateData.target);
        }

        // Check tOLPTokenId
        if (participateData.tOLPTokenId != 0) {
            if (participateData.tOLPTokenId != tOLPTokenId && tOLPTokenId != 0) {
                revert Magnetar_tOLPTokenMismatch();
            }

            tOLPTokenId = participateData.tOLPTokenId;  // @audit - does not verify sender owns that token
        }
        if (tOLPTokenId == 0) revert Magnetar_ActionParamsMismatch();

        IERC721(lockDataTarget).approve(participateData.target, tOLPTokenId);
        uint256 oTAPTokenId = ITapiocaOptionBroker(participateData.target).participate(tOLPTokenId);

        address oTapAddress = ITapiocaOptionBroker(participateData.target).oTAP();
        IERC721(oTapAddress).safeTransferFrom(address(this), user, oTAPTokenId, "0x");
    }
```

The only thing to consider is that the following line, must not revert:

```solidity
IERC721(lockDataTarget).approve(participateData.target, tOLPTokenId);
```

Since the contract will not be an owner of `tOLPTokenId`, we'll need to input a custom malicious `lockDataTarget` address, for which the approve will not revert. The `lockDataTarget` is not used at any other place within that function, so there'll be no problem inputting a malicious address here.

After doing the described steps above, the attacker will lock the innocent user's `tOLP` and get the `oTAP` NFT minted to themselves, effectively stealing the innocent user's NFT.

### Recommended Mitigation Steps

Verify that the sender owns that `tOLP` id.

### Assessed type

ERC721

**[0xWeiss (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/54#issuecomment-2125595709)**

***

## [[H-11] Adversary can utilise approved to Magnetar `oTAP` and `tOLP` NFTs](https://github.com/code-423n4/2024-02-tapioca-findings/issues/45)
*Submitted by [deadrxsezzz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/45)*

The idea of Magnetar is to allow users to batch transactions towards certain contract within the Tapioca contracts, including `TapiocaOptionBroker` and `TapiocaOptionLiquidityProvision`. In order to do so, users will have to give `oTAP` and `tOLP` allowance to the Magnetar contract.

The problem is that within the `_processTapTokenOperation` function, any user could make a call for another's user's approved NFT, as there are no checks that the `msg.sender` is the owner of the NFT.

```solidity
    function _processTapTokenOperation(
        address _target,
        bytes calldata _actionCalldata,
        uint256 _actionValue,
        bool _allowFailure
    ) private {
        if (!cluster.isWhitelisted(0, _target)) revert Magnetar_NotAuthorized(_target, _target);

        bytes4 funcSig = bytes4(_actionCalldata[:4]);
        if (
            funcSig == ITapiocaOptionBroker.exerciseOption.selector
                || funcSig == ITapiocaOptionBroker.participate.selector
                || funcSig == ITapiocaOptionBroker.exitPosition.selector
                || funcSig == ITapiocaOptionLiquidityProvision.lock.selector
                || funcSig == ITapiocaOptionLiquidityProvision.unlock.selector
        ) {
            _executeCall(_target, _actionCalldata, _actionValue, _allowFailure);
            return;
        }
        revert Magnetar_ActionNotValid(MagnetarAction.TapToken, _actionCalldata);
    }
```

Example: A user can call `exerciseOption` for another person's approved `oTAP` and exercise their option:

```solidity
    function exerciseOption(uint256 _oTAPTokenID, ERC20 _paymentToken, uint256 _tapAmount) external whenNotPaused {
        // Load data
        (, TapOption memory oTAPPosition) = oTAP.attributes(_oTAPTokenID);
        LockPosition memory tOLPLockPosition = tOLP.getLock(oTAPPosition.tOLP);
        bool isPositionActive = _isPositionActive(tOLPLockPosition);
        if (!isPositionActive) revert OptionExpired();

        uint256 cachedEpoch = epoch;

        PaymentTokenOracle memory paymentTokenOracle = paymentTokens[_paymentToken];

        // Check requirements
        if (paymentTokenOracle.oracle == ITapiocaOracle(address(0))) {
            revert PaymentTokenNotSupported();
        }
        if (!oTAP.isApprovedOrOwner(msg.sender, _oTAPTokenID)) {
            revert NotAuthorized();
        }
        if (block.timestamp < oTAPPosition.entry + EPOCH_DURATION) {
            revert OneEpochCooldown();
        } // Can only exercise after 1 epoch duration

        // Get eligible OTC amount
        uint256 gaugeTotalForEpoch = singularityGauges[cachedEpoch][tOLPLockPosition.sglAssetID];
        uint256 netAmount = uint256(netDepositedForEpoch[cachedEpoch][tOLPLockPosition.sglAssetID]);
        if (netAmount == 0) revert NoLiquidity();
        uint256 eligibleTapAmount = muldiv(tOLPLockPosition.ybShares, gaugeTotalForEpoch, netAmount);
        eligibleTapAmount -= oTAPCalls[_oTAPTokenID][cachedEpoch]; // Subtract already exercised amount
        if (eligibleTapAmount < _tapAmount) revert TooHigh();

        uint256 chosenAmount = _tapAmount == 0 ? eligibleTapAmount : _tapAmount;
        if (chosenAmount < 1e18) revert TooLow();
        oTAPCalls[_oTAPTokenID][cachedEpoch] += chosenAmount; // Adds up exercised amount to current epoch

        // Finalize the deal
        _processOTCDeal(_paymentToken, paymentTokenOracle, chosenAmount, oTAPPosition.discount);

        emit ExerciseOption(cachedEpoch, msg.sender, _paymentToken, _oTAPTokenID, chosenAmount);
    }
```

### Recommended Mitigation Steps

Add checks within Magnetar that the user owns the NFT on which they're making a call.

### Assessed type

Access Control

**[0xWeiss (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/45#issuecomment-2125597715)**

***

## [[H-12] Adversary can steal user's NFT's if they have set Magnetar as `isApprovedForAll == true`](https://github.com/code-423n4/2024-02-tapioca-findings/issues/44)
*Submitted by [deadrxsezzz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/44)*

Since Magnetar is supposed to be used as a router for multiple operations, it can be expected that user will have it pre-approved for their NFTs (such as `tOLP` as `oTAP` ones, as they'll be the ones primarily used).

The Magnetar contract allows for any user to make a `ERC721.approve`, via `_processPermitOperation`:

```solidity
    function _processPermitOperation(address _target, bytes calldata _actionCalldata, bool _allowFailure) private {
        if (!cluster.isWhitelisted(0, _target)) revert Magnetar_NotAuthorized(_target, _target);

        /// @dev owner address should always be first param.
        // permitAction(bytes,uint16)
        // permit(address owner...)
        // revoke(address owner...)
        // permitAll(address from,..)
        // permit(address from,...)
        // setApprovalForAll(address from,...)
        // setApprovalForAsset(address from,...)
        bytes4 funcSig = bytes4(_actionCalldata[:4]);
        if (
            funcSig == IPermitAll.permitAll.selector || funcSig == IPermitAll.revokeAll.selector
                || funcSig == IPermit.permit.selector || funcSig == IPermit.revoke.selector
                || funcSig == IYieldBox.setApprovalForAll.selector || funcSig == IYieldBox.setApprovalForAsset.selector 
                || funcSig == IERC20.approve.selector || funcSig == IPearlmit.approve.selector
                || funcSig == IERC721.approve.selector 
        ) {
            /// @dev Owner param check. See Warning above.
            _checkSender(abi.decode(_actionCalldata[4:36], (address)));
            // No need to send value on permit
            _executeCall(_target, _actionCalldata, 0, _allowFailure);
            return;
        }
        revert Magnetar_ActionNotValid(MagnetarAction.Permit, _actionCalldata);
    }
```

The problem is that for OZ ERC721s (such as `oTAP` and `tOLP`), if an NFT owner has approved a spender as `isApprovedForAll`, the spender can call `approve` for any NFTs belonging to the owner.

In other words, if user A has set Magnetar as `approvedForAll`, user B can call `NFT.approve(userB, id)` and get access to user A's NFT:

```solidity
    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ERC721.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(
            _msgSender() == owner || isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not token owner or approved for all"
        );

        _approve(to, tokenId);
    }
```

### Recommended Mitigation Steps

Do not allow users to make a call with  `ERC721.approve` selector.

**[0xWeiss (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/44#issuecomment-2125599377)**

***
 
# Medium Risk Findings (32)
## [[M-01] Missing unwrap configuration when withdrawing cross-chain in the `depositYBLendSGLLockXchainTOLP()` function of `MagnetarAssetXChainModule` results in being unable to lock and participate on the destination chain](https://github.com/code-423n4/2024-02-tapioca-findings/issues/180)
*Submitted by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/180), also found by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/138), [deadrxsezzz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/89), and cccz ([1](https://github.com/code-423n4/2024-02-tapioca-findings/issues/26), [2](https://github.com/code-423n4/2024-02-tapioca-findings/issues/25))*

The `depositYBLendSGLLockXchainTOLP()` function attempts to lend into Singularity, then withdraws the Singularity tokens cross-chain to lock and participate on the destination chain. The Singularity tokens are wrapped as TOFT tokens to facilitate cross-chain transfer.

```solidity
uint256 fraction =
    _depositYBLendSGL(data.depositData, data.singularity, IYieldBox(yieldBox), data.user, data.lendAmount);

// wrap SGL receipt into tReceipt
// ! User should approve `address(this)` for `IERC20(data.singularity)` !
uint256 toftAmount = _wrapSglReceipt(IYieldBox(yieldBox), data.singularity, data.user, fraction, data.assetId);
```

This function calls `_withdrawToChain()` with the `unwrap` parameter set to false, indicating that TOFT-wrapped Singularity tokens will not be unwrapped upon receipt on the destination chain.

```solidity
_withdrawToChain(
    MagnetarWithdrawData({
        yieldBox: yieldBox,
        assetId: data.assetId,
        unwrap: false,
        lzSendParams: data.lockAndParticipateSendParams.lzParams,
        sendGas: data.lockAndParticipateSendParams.lzSendGas,
        composeGas: data.lockAndParticipateSendParams.lzComposeGas,
        sendVal: data.lockAndParticipateSendParams.lzSendVal,
        composeVal: data.lockAndParticipateSendParams.lzComposeVal,
        composeMsg: data.lockAndParticipateSendParams.lzParams.sendParam.composeMsg,
        composeMsgType: data.lockAndParticipateSendParams.lzComposeMsgType,
        withdraw: true
    })
);
```

However, the [`TapiocaOptionLiquidityProvision.lock()`](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/options/TapiocaOptionLiquidityProvision.sol#L187) function attempts to acquire YieldBox's shares of the original Singularity tokens. Therefore, upon receiving wrapped Singularity tokens on the destination chain, it should unwrap these tokens to facilitate the execution of subsequent actions.

### Impact

`depositYBLendSGLLockXchainTOLP()` will fail to execute the locking process after receiving wrapped Singularity tokens cross-chain.

### Recommended Mitigation Steps

`depositYBLendSGLLockXchainTOLP()` should call `_withdrawToChain()` with `unwrap` set to true.

### Assessed type

Context

**[cryptotechmaker (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/180#issuecomment-2031959346):**
 > Fixed [here](https://github.com/Tapioca-DAO/tapioca-periph/pull/204).

***

## [[M-02] `tOLP` positions created through `MagnetarAction.Permit` can be stolen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/176)
*Submitted by [immeas](https://github.com/code-423n4/2024-02-tapioca-findings/issues/176), also found by [immeas](https://github.com/code-423n4/2024-02-tapioca-findings/issues/168)*

<https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/Magnetar.sol#L199-L212>

<https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/Magnetar.sol#L304-L305>

### Description

This issue is a combination of three other issues:

- `MagnetarAction.TapToken` integration will leave tokens stuck in `Magnetar` contract.
- A lot of calls in `MagnetarAction.Permit` enables anyone to steal whitelisted tokens held by `Magnetar`.
- Anyone can take any whitelisted tokens approved to `Magnetar`.

In short, the first issue describes that, due to how `MagnetarAction.TapToken` is setup, it will leave the `tOLP` position a user creates through [`TapiocaOptionBroker::participate`](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/options/TapiocaOptionBroker.sol#L301) stuck in the `Magnetar` contract. As it mints the position to `msg.sender` which will be the `Magnetar` contract:

```solidity
File: tap-token/contracts/options/TapiocaOptionBroker.sol

301:        oTAPTokenID = oTAP.mint(msg.sender, lockExpiry, uint128(target), _tOLPTokenID);
```

The two following ones:

Firstly, describes how anyone can take any tokens that are in the `Magnetar` contract by granting themselves permissions to transfer any whitelisted tokens in using `MagnetarAction.Permit`. Because of how [`MagnetarStorage::_checkSender`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/MagnetarStorage.sol#L93-L97) validates that the first argument in the calldata to `MagnetarAction.Permit` is the same as `msg.sender`. This together with that a lot of the calls allowed through `MagnetarAction.Permit` (`IYieldBox::setApprovalForAll`, `IYieldBox::setApprovalForAsset`, `IERC20::approve`, and `IERC721::approve`) have `address to`; i.e. the operator/approvee as the first argument. Hence, any user can approve themselves to transfer tokens out of the contract.

Secondly, by using `MagnetarAction.OFT`; which allows anyone to transfer tokens out of `Magnetar` (and steal any approved tokens to `Magnetar`) since there is an unvalidated call done to any whitelisted contract in [`MagnetarAction.OFT`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/Magnetar.sol#L325-L333).

The contract is not in itself supposed to hold any tokens; in itself these issues are not that severe by themselves. However, these issues combined allows an attacker to steal the position completely. Since the first one makes the position be stuck in `Magnetar` and the two last ones makes it not actually stuck, but retrievable by anyone.

### Impact

If a user uses `MagnetarAction.TapToken` to create their position they can have their position and/or rewards stolen.

### Proof of Concept

Test in `tap-token/test/Magnetar.t.sol`, builds on the test described in `MagnetarAction.TapToken` integration will leave tokens stuck in `Magnetar` contract:

```solidity
    address attacker = makeAddr("Attacker");

    function testStealTokensStuckInMagnetar() public {
        testMagnetarParticipateOTAPStuckInMagnetar();

        MagnetarCall memory approve = MagnetarCall({
            id: MagnetarAction.Permit,
            target: address(oTAP),
            value: 0,
            allowFailure: false,
            call: abi.encodeWithSelector(IERC721.setApprovalForAll.selector, address(attacker), true)
        });

        MagnetarCall[] memory calls = new MagnetarCall[](1);
        calls[0] = approve;

        vm.startPrank(attacker);
        magnetar.burst(calls);
        oTAP.transferFrom(address(magnetar), address(attacker), 1);
        vm.stopPrank();

        assertEq(oTAP.ownerOf(1),address(attacker));
    }
```

Full test with setup can be found [here](https://gist.github.com/0ximmeas/99606148ff878591c20d5124cab0c617).

### Recommended Mitigation Steps

Consider implementing the mitigations described in the three mentioned referenced issues:

- Adding the ability for the caller to declare a receiver in `TapiocaOptionBroker::participate` and `exerciseOption`. Similar to how it's done in `TapiocaOptionLiquidityProvision::lock`.
- Rethinking how `MagnetarAction.Permit` should work. As there is support in modules for a lot of the calls it is used for perhaps it is unnecessary to have.
- Removing the general `MagnetarAction.OFT` call. Most of the interactions with the contracts in the Tapioca ecosystem is already handled in the Magnetar module system which handles approvals and transfers.

### Assessed type

Invalid Validation

**[cryptotechmaker (Tapioca) disagreed with severity and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/176#issuecomment-2009676677):**
 > The last 2 seems possible only if you approve the attacker, which is valid even for any random ERC20.
> 
> The first one can be an issue, but I don't think the severity should be H. Maybe Medium or Low. I'll let @0xRektora confirm as well.

**[0xRektora (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/176#issuecomment-2015016770):**
 > While this is a valid finding, the probability of it happening are very low. Will still put it as `medium` due to the nature of the issue.
> 
> > MagnetarAction.TapToken integration will leave tokens stuck in Magnetar contract. A lot of calls in MagnetarAction. Permit enables anyone to steal whitelisted tokens held by Magnetar.
> 
> We don't actually use TapToken singular actions, instead we use the `MagnetarOptionModule`. As for permits, we use `TapiocaOmnichainEngine/OFT` for that.
> 
> The probability are very low because the flow of action taken to the casual user is dictated by a different code. While this is possible to happen it'd have to be an advanced user, who probably will batch the actions together of permitting/locking/sending the token to his address. The Tx will revert if those are not done in the same Tx using Magnetar batching.

**[LSDan (judge) decreased severity to Medium](https://github.com/code-423n4/2024-02-tapioca-findings/issues/176#issuecomment-2034831156)**

***

## [[M-03] Spearbit finding "It is possible to exercise TAP option an extra time compared to lock duration" not fixed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/175)
*Submitted by [immeas](https://github.com/code-423n4/2024-02-tapioca-findings/issues/175)*

<https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/options/TapiocaOptionBroker.sol#L408-L414>

<https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/options/TapiocaOptionBroker.sol#L292-L298>

### Description

The finding itself is a follow up on the C4 finding [#189](https://github.com/code-423n4/2023-07-tapioca-findings/issues/189). The description of the issue can be found in the Spearbit report.

The mitigation introduced in the [PR](https://github.com/Tapioca-DAO/tap-token/pull/155) seems lost in the code base at audit here.

### Impact

Quoting the impact from the Spearbit report:

> Attacker has removed one epoch of rewards from the long term stakers, receiving 2 tapOFT payoffs for 1 epoch long staking. More generally, an attacker can add 1 epoch of option rewards in excess to their actual locking time (as epsilon can be made minutes long and not significant position locking wise).
> This is a violation of base protocol [token economy](https://docs.tapioca.xyz/tapioca/token-economy/token-economy#call-option-incentive-tap-otap:\~:text=Lenders%20with%20active%20oTAP%20positions%20will%20receive%20oTAP%20shares%20from%20the%20DSO%20program%20every%20week%20that%20their%20position%20remains%20locked%2C%20proportional%20to%20their%20positions%20share%20of%20the%20total%20supplied%20locked%20liquidity%20in%20the%20respective%20market%2C):
>
> > Lenders with active oTAP positions will receive oTAP shares from the DSO program every week that their position remains locked, proportional to their positions share of the total supplied locked liquidity in the respective market

### Proof of Concept

Test showing the issue is still there in `tap-token/test/OptionTest.t.sol`:

```solidity
    function testExerciseOptionTwice() public {
        pearlmit.approve(address(yieldbox), 1, address(tOLP), type(uint200).max, type(uint48).max);
        paymentToken.mint(address(this),1000e18);
        paymentToken.approve(address(pearlmit),type(uint256).max);
        pearlmit.approve(address(paymentToken), 0, address(tOB), type(uint200).max, type(uint48).max);

        // epoch timestamps
        uint256 epoch2 = block.timestamp + 7 days;
        uint256 epoch3 = epoch2 + 7 days;

        // step 1 participate right before end of epoch
        vm.warp(epoch2 - 5 minutes);

        uint256 tOLPId = tOLP.lock({
            _to: address(this),
            _singularity: IERC20(singularity), 
            _lockDuration: 7 days + 10 minutes,
            _ybShares: 1e18
        });

        tOLP.approve(address(pearlmit), tOLPId);
        pearlmit.approve(address(tOLP), tOLPId, address(tOB), 1, type(uint48).max);
        tOB.participate(tOLPId);

        // epoch changes
        vm.warp(epoch2);
        tOB.newEpoch();

        // step 2 right as you can, exercise first option
        vm.warp(epoch3 - 5 minutes);     
        tOB.exerciseOption(tOLPId, paymentToken, 0);

        vm.warp(epoch3);
        tOB.newEpoch();

        // step 3 just after epoch 3 trigger, collect 2nd option
        vm.warp(epoch3 + 10 minutes);
        tOB.exerciseOption(tOLPId, paymentToken, 0);

        oTAP.approve(address(tOB), tOLPId);
        tOB.exitPosition(tOLPId);
        tOLP.unlock(tOLPId,IERC20(singularity),address(this));
    }
```

The full test file with setup can be found [here](https://gist.github.com/0ximmeas/d116af8b8631ec9e8d1a6d150bb60cbb)

### Recommended Mitigation Steps

Consider re-applying the same fix that was acknowledged in the Spearbit audit.

### Assessed type

Timing

**[0xRektora (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/175#issuecomment-2016879451)**

**[cryptotechmaker (Tapioca) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/175#issuecomment-2033791299):**
 > Fixed [here](https://github.com/Tapioca-DAO/tap-token/pull/174).

***

## [[M-04] anyone with a `Pearlmit` approval to transfer `TapToken` can have their funds stolen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/172)
*Submitted by [immeas](https://github.com/code-423n4/2024-02-tapioca-findings/issues/172), also found by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/152), [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/118), and [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/75)*

When transferring `TapToken` there is an extra check done in [`BaseTapiocaOmnichainEngine::transferFrom`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/BaseTapiocaOmnichainEngine.sol#L63-L67):

```solidity
File: tapioca-periph/contracts/tapiocaOmnichainEngine/BaseTapiocaOmnichainEngine.sol

63:        if (allowance(from, spender) < value) {
64:            // _transfer(from, to, value);
65:            bool isErr = pearlmit.transferFromERC20(from, to, address(this), value);
66:            if (isErr) revert BaseTapiocaOmnichainEngine_NotValid();
67:        } else {
```

Here there's if the spender is not allowed, the allowance is checked in `Pearlmit`. The issue is that, `Pearlmit` checks the allowance against `msg.sender` which in this case will be the `TapToken` contract. Hence, any user with an allowance to the `TapToken` contract in `Pearlmit` can have their `TAP` stolen.

### Impact

If a user has allowed `TapToken` to transfer `TapToken` through `Pearlmit`, they can have all they have approved stolen. Since `TapToken` does a lot of token handling in composed messages, this is likely to happen.

### Proof of Concept

Test in `tap-token/test/TapToken.t.sol`:

```solidity
    function testStealTapTokenUsingPearlmitAllowanceToTapToken() public {
        deal(address(aTapOFT), userA, 1e18);
        assertEq(aTapOFT.balanceOf(userA), 1e18);
        assertEq(aTapOFT.balanceOf(userB), 0);

        // userA allows TapToken to transfer TapTokens
        vm.startPrank(userA);
        pearlmit.approve(address(aTapOFT), 0, address(aTapOFT), 1e18, type(uint48).max);
        aTapOFT.approve(address(pearlmit), 1e18);
        vm.stopPrank();

        // userB sees this and uses that allowance to transfer to themselves
        vm.prank(userB);
        aTapOFT.transferFrom(userA,userB, 1e18);
        
        assertEq(aTapOFT.balanceOf(userA), 0);
        assertEq(aTapOFT.balanceOf(userB), 1e18);
    }
```

### Recommended Mitigation Steps

Consider not doing the fallback to `Pearlmit` in `transferFrom`.

### Assessed type

Access Control

**[cryptotechmaker (Tapioca) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/172#issuecomment-2009720953):**
 > Low/Invalid; The issue seems a bit out of context. The link provided is from `BaseTapiocaOmnichainEngine` and there's no context provided from which part this is triggered on TapToken.
> 
> Also this would be possible only if the approve in pearlmit is done with a large enough deadline and amount someone else can exploit. All pearlmit approvals have a deadline associated with them.

**[0xRektora (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/172#issuecomment-2016878574):**
 > I'd keep it as medium. Potential side effects might happen on current/future TOE tokens.

***

## [[M-05] `depositRepayAndRemoveCollateralFromMarket` function of MagnetarAssetModule can't be used on behalf of user](https://github.com/code-423n4/2024-02-tapioca-findings/issues/158)
*Submitted by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/158), also found by [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/93)*

Functions of Magnetar are intended to be callable from whitelisted addresses on behalf of users. This serves purposes such as allowing TOFT or USDT contracts to execute Magnetar functions during lzReceive (receiving tokens cross-chain).

All Magnetar functions use `_checkSender` to allow whitelisted sender:

```solidity
function _checkSender(address _from) internal view {
    if (_from != msg.sender && !cluster.isWhitelisted(0, msg.sender)) {
        revert Magnetar_NotAuthorized(msg.sender, _from);
    }
}
```

However, in the `depositRepayAndRemoveCollateralFromMarket` function of MagnetarAssetModule, it calls `_extractTokens` with the `msg.sender` address to pull tokens from the sender. Therefore, if `msg.sender` is different from `data.user` (the sender calling on behalf of the user), this function still pulls tokens from the sender. This behavior is incorrect, resulting in pulling tokens from the wrong address or reverting due to insufficient balance and allowance of `msg.sender`.

```solidity
function depositRepayAndRemoveCollateralFromMarket(DepositRepayAndRemoveCollateralFromMarketData memory data)
    public
    payable
{
    // Check sender
    _checkSender(data.user);

    ...

    // @dev deposit to YieldBox
    if (data.depositAmount > 0) {
        data.depositAmount = _extractTokens(msg.sender, assetAddress, data.depositAmount);
        IERC20(assetAddress).approve(address(_yieldBox), 0);
        IERC20(assetAddress).approve(address(_yieldBox), data.depositAmount);
        _yieldBox.depositAsset(assetId, address(this), address(this), data.depositAmount, 0);
    }

    ...
```

### Impact

Senders will be at risk of losses due to mistakenly pulling tokens or facing a DOS attack when calling `depositRepayAndRemoveCollateralFromMarket` on behalf of the user. This intended functionality will be broken.

### Recommended Mitigation Steps

Should `_extractTokens` from `data.user` instead of `msg.sender`.

```solidity
data.depositAmount = _extractTokens(msg.sender, assetAddress, data.depositAmount);
```

**[cryptotechmaker (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/158#issuecomment-2034564686):**
 > Fixed [here](https://github.com/Tapioca-DAO/tapioca-periph/commit/e5e23c447a7e208d7a11faf219d6dffc93aaac4c).

***

## [[M-06] `depositYBLendSGLLockXchainTOLP` function of the MagnetarAssetXChainModule will not work because it transfers Singularity tokens to the user before `_withdrawToChain`](https://github.com/code-423n4/2024-02-tapioca-findings/issues/157)
*Submitted by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/157)*

<https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarAssetXChainModule.sol#L85-L114>

<https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarAssetCommonModule.sol#L52-L63>

### Description

In `depositYBLendSGLLockXchainTOLP` function of the MagnetarAssetXChainModule, after lending to SGL, it will wrap the received Singularity tokens into the TOFT wrapping token of it. Afterward, it attempts to transfer those wrapped tokens cross-chain, then unwrap them in the destination chain to lock and participate.

```solidity
function depositYBLendSGLLockXchainTOLP(DepositAndSendForLockingData memory data) public payable {
    ...
    uint256 fraction =
        _depositYBLendSGL(data.depositData, data.singularity, IYieldBox(yieldBox), data.user, data.lendAmount);

    // wrap SGL receipt into tReceipt
    // ! User should approve `address(this)` for `IERC20(data.singularity)` !
    uint256 toftAmount = _wrapSglReceipt(IYieldBox(yieldBox), data.singularity, data.user, fraction, data.assetId);

    data.lockAndParticipateSendParams.lzParams.sendParam.amountLD = toftAmount;

    // decode `composeMsg` and re-encode it with updated params
    (uint16 msgType_,, uint16 msgIndex_, bytes memory tapComposeMsg_, bytes memory nextMsg_) =
    TapiocaOmnichainEngineCodec.decodeToeComposeMsg(data.lockAndParticipateSendParams.lzParams.sendParam.composeMsg);

    LockAndParticipateData memory lockData = abi.decode(tapComposeMsg_, (LockAndParticipateData));
    lockData.fraction = toftAmount;

    data.lockAndParticipateSendParams.lzParams.sendParam.composeMsg =
        TapiocaOmnichainEngineCodec.encodeToeComposeMsg(abi.encode(lockData), msgType_, msgIndex_, nextMsg_);

    // send on another layer for lending
    _withdrawToChain(
        MagnetarWithdrawData({
            yieldBox: yieldBox,
            assetId: data.assetId,
            unwrap: false,
            lzSendParams: data.lockAndParticipateSendParams.lzParams,
            sendGas: data.lockAndParticipateSendParams.lzSendGas,
            composeGas: data.lockAndParticipateSendParams.lzComposeGas,
            sendVal: data.lockAndParticipateSendParams.lzSendVal,
            composeVal: data.lockAndParticipateSendParams.lzComposeVal,
            composeMsg: data.lockAndParticipateSendParams.lzParams.sendParam.composeMsg,
            composeMsgType: data.lockAndParticipateSendParams.lzComposeMsgType,
            withdraw: true
        })
    );
}
```

After lending into the Singularity contract, `_wrapSglReceipt` is used to wrap the received Singularity tokens into TOFT tokens. Thus, they will be able to be sent cross-chain by using `_withdrawToChain` with composed messages including the `lockAndParticipate` option to perform these actions after receiving tokens

The `_withdrawToChain` function attempts to withdraw YieldBox shares of this contract (address(this)) to obtain tokens before sending them cross-chain (see this [code snippet](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarBaseModule.sol#L69)). However, `_wrapSglReceipt` has sent tokens to the user after wrapping. Therefore, there are no tokens or YieldBox shares existing in this contract, resulting in `_withdrawToChain` reverting afterward.

```solidity
function _wrapSglReceipt(IYieldBox yieldBox, address sgl, address user, uint256 fraction, uint256 assetId)
    internal
    returns (uint256 toftAmount)
{
    IERC20(sgl).safeTransferFrom(user, address(this), fraction);

    (, address tReceiptAddress,,) = yieldBox.assets(assetId);

    IERC20(sgl).approve(tReceiptAddress, fraction);
    toftAmount = ITOFT(tReceiptAddress).wrap(address(this), address(this), fraction);
    IERC20(tReceiptAddress).safeTransfer(user, toftAmount);
}
```

### Impact

`depositYBLendSGLLockXchainTOLP` function of MagnetarAssetXChainModule will be broken.

### Recommended Mitigation Steps

Should deposit into YieldBox for address(this) after wrapping Singularity tokens in the `_wrapSglReceipt` function as following:

```solidity
function _wrapSglReceipt(IYieldBox yieldBox, address sgl, address user, uint256 fraction, uint256 assetId)
    internal
    returns (uint256 toftAmount)
{
    IERC20(sgl).safeTransferFrom(user, address(this), fraction);

    (, address tReceiptAddress,,) = yieldBox.assets(assetId);

    IERC20(sgl).approve(tReceiptAddress, fraction);
    toftAmount = ITOFT(tReceiptAddress).wrap(address(this), address(this), fraction);
    
    //deposit to YieldBox for this 
    IERC20(tReceiptAddress).safeApprove(address(yieldBox), toftAmount);
    yieldBox.depositAsset(assetId, address(this), address(this), toftAmount, 0);
}
```

**[cryptotechmaker (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/157#issuecomment-2046771041):**
 > PR [here](https://github.com/Tapioca-DAO/tapioca-periph/pull/226).

***

## [[M-07] `_lockOnTOB` function of MagnetarMintCommonModule will not work due to the missing approved asset for YieldBox before depositing](https://github.com/code-423n4/2024-02-tapioca-findings/issues/156)
*Submitted by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/156), also found by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/139)*

In MagnetarMintCommonModule, the `_lockOnTOB` function is used to pull the singularity tokens from the user and lock them into the TapiocaOptionBroker contract.

```solidity
function _lockOnTOB(
    IOptionsLockData memory lockData,
    IYieldBox yieldBox_,
    uint256 fraction,
    bool participate,
    address user,
    address singularityAddress
) internal returns (uint256 tOLPTokenId) {
    tOLPTokenId = 0;
    if (lockData.lock) {
        if (!cluster.isWhitelisted(0, lockData.target)) {
            revert Magnetar_TargetNotWhitelisted(lockData.target);
        }
        if (lockData.fraction > 0) fraction = lockData.fraction;

        // retrieve and deposit SGLAssetId registered in tOLP
        (uint256 tOLPSglAssetId,,) =
            ITapiocaOptionLiquidityProvision(lockData.target).activeSingularities(singularityAddress);
        if (fraction == 0) revert Magnetar_ActionParamsMismatch();

        //deposit to YieldBox
        _extractTokens(user, singularityAddress, fraction);
        yieldBox_.depositAsset(tOLPSglAssetId, address(this), address(this), fraction, 0);
        ...
    }
}
```

In the above code snippet, `_extractTokens` is used to pull singularity tokens from the user to this contract. Afterward, it will deposit these tokens into YieldBox to get YieldBox shares and then lock them in the TOB contract. However, it misses approving Singularity tokens before depositing them into YieldBox. YieldBox will attempt to pull tokens from this contract (from `== address(this)`), so it will revert as YieldBox can't transfer tokens due to insufficient allowance during `yieldBox_.depositAsset()`.

### Impact

The functions of Magnetar which call `_lockOnTOB` will be broken, including the `mintBBLendSGLLockTOLP` function of MagnetarMintModule and the `lockAndParticipate` function of MagnetarMintXChainModule.

### Recommended Mitigation Steps

Should approve Singularity tokens before depositing them into YieldBox:

```solidity
//deposit to YieldBox
_extractTokens(user, singularityAddress, fraction);
singularityAddress.safeApprove(address(yieldBox_), fraction);
yieldBox_.depositAsset(tOLPSglAssetId, address(this), address(this), fraction, 0);
```

**[cryptotechmaker (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/156#issuecomment-2034717792):**
 > PR [here](https://github.com/Tapioca-DAO/tapioca-periph/commit/ffa95068b8449f65cc00b6a451b7de82c7a0fff4).

***

## [[M-08] Incorrect return value of function `BaseTapiocaOmnichainEngine._payNative()`](https://github.com/code-423n4/2024-02-tapioca-findings/issues/153)
*Submitted by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/153)*

According to the function `_payNative(_nativeFee)` described in the [LayerZero codebase](https://github.com/LayerZero-Labs/LayerZero-v2/blob/142846c3d6d51e3c2a0852c41b4c2b63fcda5a0a/oapp/contracts/oapp/OAppSender.sol#L93-L103), it is designed to return the native fee associated with the message. However, when a contract intends to initiate multiple LayerZero messages within a single transaction, more than just `_nativeFee` may be required from the sender to execute such messages.

The contract `BaseTapiocaOmnichainEngine()` facilitates multiple LayerZero messages within the Magnetar contract and the Tap token contract. Therefore, the function `_payNativeFee()` needs to be overridden to return an amount of native tokens greater than just `_nativeFee`. However, in the current implementation of the function `BaseTapiocaOmnichainEngine._payNative()`, it still returns the value of the input `_nativeFee`.

```solidity
/**
 * @inheritdoc OAppSender
 * @dev Overwrite to check for < values.
 */
function _payNative(uint256 _nativeFee) internal override returns (uint256 nativeFee) {
    if (msg.value < _nativeFee) revert NotEnoughNative(msg.value);
    return _nativeFee;
}
```

### Impact

As only `_nativeFee` will be sent along with the cross-chain message, the remaining amount `msg.value - _nativeFee` will become trapped in the `BaseTapiocaOmnichainEngine` contract. This amount can be larger than just the fee to execute the transaction since the `Magnetar` also supports the `LzComposeOption`, which defines the `msg.value` used to execute the compose option.

Due to the insufficient native tokens provided for the multiple LayerZero messages, certain functions cannot be executed (e.g., `MagnetarBaseModule._lzCustomWithdraw()`, `TapTokenReceiver._claimTwpTapRewardsReceiver()`, ...).

### Recommended Mitigation Steps

Consider modifying function `BaseTapiocaOmnichainEngine._payNative()` as follows:

```solidity
function _payNative(uint256 _nativeFee) internal override returns (uint256 nativeFee) {
    if (msg.value < _nativeFee) revert NotEnoughNative(msg.value);
    return msg.value;
}
```

### Assessed type

Context

**[LSDan (judge) decreased severity to Medium](https://github.com/code-423n4/2024-02-tapioca-findings/issues/153#issuecomment-2010495568)**

**[0xWeiss (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/153#issuecomment-2125600748)**

***

## [[M-09] Magnetar's `mintBBLendSGLLockTOLP` reverts when `lock` is set to false](https://github.com/code-423n4/2024-02-tapioca-findings/issues/140)
*Submitted by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/140), also found by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/182)*

The `mintBBLendSGLLockTOLP` function in Magnetar is designed to mint `USDO` tokens from bigbang, deposit them to singularity, lock the liquidity in the `TOLP` contract and then participate in the `TOB` contract.

The function is designed to be modular, so the user can choose to skip any of the steps and still have the other execute. The issue is that if the user decides not lock in the `TOLP` contract, the function will revert since it is pulling tokens from the wrong address.

After the market operations, the function does two operations for locking, as shown below:

```solidity
uint256 tOLPTokenId = _lockOnTOB(
    data.lockData,
    yieldBox_,
    fraction,
    data.participateData.participate,
    data.user,
    data.externalContracts.singularity
);

if (data.participateData.participate) {
    _participateOnTOLP(data.participateData, data.user, data.lockData.target, tOLPTokenId);
}
```

In the `_lockOnTOB` function, there is a check which allows the user to skip this step based on their input:

```solidity
if (lockData.lock) {
    //...
}
```

However, if this step is skipped, then the `TOLP` NFT position will still be with the user; thus, needs to be pulled from the user for the `participate` step. But in the `participate` step, we see that the code expects the token to be with the Magnetar contract already.

```solidity
IERC721(lockDataTarget).approve(participateData.target, tOLPTokenId);
uint256 oTAPTokenId = ITapiocaOptionBroker(participateData.target).participate(tOLPTokenId);

address oTapAddress = ITapiocaOptionBroker(participateData.target).oTAP();
IERC721(oTapAddress).safeTransferFrom(address(this), user, oTAPTokenId, "0x");
```

This would only be true if the previous step's `lock` function had run. This is because when locking the tokens, the Magnetar contract receives the NFT position if participate function is set to be run. If the `lock` function is skipped, the `participate` function will revert since the NFT position is still with the user.

### Proof of Concept

During the `lock` function call, we see that the Magnetar contract tries to credit itself the NFT tokens.

```solidity
tOLPTokenId = ITapiocaOptionLiquidityProvision(lockData.target).lock(
    participate ? address(this) : user, singularityAddress, lockData.lockDuration, lockData.amount
);
```

However, if the lock functionality is skipped, then the Magnetar contract will not own the tokens since this step will not be run. Users will be forced to raw send the NFT position to the magnetar contract which is unsafe since the Magnetar contract is not designed to hold tokens.

### Recommended Mitigation Steps

If `lockData.lock` was true, the `_participateOnTOLP` function should pull the NFT positions from the user to the Magnetsar contract.

**[cryptotechmaker (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/140#issuecomment-2036433567):**
 > PR [here](https://github.com/Tapioca-DAO/tapioca-periph/commit/160d198bcdc435f2bccc046016ce7db1bc09575d).

***

## [[M-10] Magnetar unwrap operations broken due to bad ownership and checks](https://github.com/code-423n4/2024-02-tapioca-findings/issues/137)
*Submitted by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/137)*

The `_processWrapOperation` function can be triggered on the Magnetar contract to wrap/unwrap the user's tokens into or out of the TOFT contracts. This function allows 2 selectors, `wrap` and `unwrap` to be called.

The issue is that `unwrap` function has 2 issues which prevent it from working properly. Below is the code from the `BaseTOFT.sol` contract, showing the implementation of the `unwrap`: function.

```solidity
function _unwrap(address _toAddress, uint256 _amount) internal virtual {
    _burn(msg.sender, _amount);
    vault.withdraw(_toAddress, _amount);
}
```

As seen here, the token is burnt from the `msg.sender` address. However, the `_processWrapOperation` function in the Magnetar contract does not transfer out the token from the user's address to itself before calling `_unwrap`.

```solidity
if (funcSig == ITOFT.wrap.selector || funcSig == ITOFT.unwrap.selector) {
    /// @dev Owner param check. See Warning above.
    _checkSender(abi.decode(_actionCalldata[4:36], (address)));
    _executeCall(_target, _actionCalldata, _actionValue, _allowFailure);
    return;
}
```

So the Magnetar contract isn't in possession of the token that the `TOFT` contract is trying to burn. The Magnetar contract itself is not designed to hold user tokens, since anyone can claim them. Users should not send their tokens to the Magnetar contract manually and then call this function, since MEV bots can steal tokens from this contract by just calling the unwrap function before them. Due to this, there is no way for Magnetar to actually unwrap the tokens.

Secondly, the `_checkSender` function is used to check the first passed address against `msg.sender`. the issue is that the first address passed to the `unwrap` function is the destination address, not the owner's address. The owner is assumed to be `msg.sender`. So this contract essentially only makes sure that the `msg.sender` matches the destination of the unwrapped tokens, which is not a useful check.

Since these two issues break the functionality of this function, this is a medium severity issue.

### Proof of Concept

The fact that Magnetar isn't designed to hold tokens is evident from the fact that any user can just call the unwrap function from magnetar and burn up any tokens it is currently holding. So the absence of the transferring of the token to the Magnetar contract itself causes an issue.

### Recommended Mitigation Steps

The `unwrap` functionality should transfer the token from the `msg.sender` to itself first. This will ensure both that the caller owns the token and that the token is in the possession of the Magnetar contract. The `_checkSender` check for the `unwrap` case is unnecessary and prevents users from choosing a destination address.

### Assessed type

Invalid Validation

**[cryptotechmaker (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/137#issuecomment-2036562263):**
 > PR [here](https://github.com/Tapioca-DAO/tapioca-periph/commit/8c89a284d46bd0243048ef9cc1b28d4401a48b62).

***

## [[M-11] `twAML` weights can be griefed by burning tokens](https://github.com/code-423n4/2024-02-tapioca-findings/issues/132)
*Submitted by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/132)*

Users can lock their liquidity in the `TOLP` contract and mint `OTAP` tokens in the `TOB` contract. The `TOB` contract has a special mechanism called `twAML` to balance out how much rewards they emit over time.

Basically, if a user commits `OTAP` tokens worth more than a minimum amount of shares, they are eligible to sway the votes:

```solidity
bool hasVotingPower =
    lock.ybShares >= computeMinWeight(pool.totalDeposited + VIRTUAL_TOTAL_AMOUNT, MIN_WEIGHT_FACTOR);
```

This allows them to influence the magnitude, divergence as well as the `twAML` value of this asset id.

```solidity
pool.averageMagnitude = (pool.averageMagnitude + magnitude) / pool.totalParticipants; // compute new average magnitude
    // Compute and save new cumulative
    divergenceForce = lock.lockDuration >= pool.cumulative;
    if (divergenceForce) {
        pool.cumulative += pool.averageMagnitude;
    } else {
        if (pool.cumulative > pool.averageMagnitude) {
            pool.cumulative -= pool.averageMagnitude;
        } else {
            pool.cumulative = 0;
        }
    }

    // Save new weight
    pool.totalDeposited += lock.ybShares;

    twAML[lock.sglAssetID] = pool
```

These values determine how large of a discount the users can get when exercising their options.

Similarly, when users decide to exit their position, or if their lock has expired, either they themselves or other users can kick them out of the `TOB` system and reset the `twAML` values to the values it was before.

```solidity
if (!isSGLInRescueMode && participation.hasVotingPower) {
    TWAMLPool memory pool = twAML[lock.sglAssetID];

    if (participation.divergenceForce) {
    //...
```

So the `twAML` change a single user can cause is limited to their lock duration. However, users also have another option: they can directly burn their `OTAP` token after participating. This is because the `OTAP` contract has an open burn function.

```solidity
function burn(uint256 _tokenId) external {
    if (!_isApprovedOrOwner(msg.sender, _tokenId)) revert NotAuthorized();
    _burn(_tokenId);

    emit Burn(msg.sender, _tokenId, options[_tokenId]);
}
```

Now, these user's contributions to the `twAML` calculations cannot be wiped out after their lock expires. This is because the `exitPosition` function calls `otap.burn` which will fail since the user has already burnt their tokens.

So users can affect the `twAML` calculations for an infinite amount of time by burning tokens. This scenario is specifically prevented in the TOLP contract which has a max lock duration enforced with `MAX_LOCK_DURATION`.

Since users can permanently affect the `twAML` calculations, this is a medium severity issue.

### Proof of Concept

Users can directly burn tokens due to `OTAP`'s open burn function as evident from the linked code. This prevents `exitPosition` being called in the `TOB` contract and thus, never resets the `twAML` values.

### Recommended Mitigation Steps

Disable the open burn function in the `OTAP` contract. Only allows selected contracts such as the `TOB` contract to call it.

### Assessed type

Math

**[0xRektora (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/132#issuecomment-2016854358)**

***

## [[M-12] A single second in an epoch makes an user eligible for the entire epoch's rewards](https://github.com/code-423n4/2024-02-tapioca-findings/issues/131)
*Submitted by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/131), also found by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/148), deadrxsezzz ([1](https://github.com/code-423n4/2024-02-tapioca-findings/issues/85), [2](https://github.com/code-423n4/2024-02-tapioca-findings/issues/65)), and [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/187)*

A user can lock their LP tokens into the `TOLP` contract, and then put their `TOLP` into the `TOB` contract to be eligible for option rewards. These option rewards are paid out every epoch and distributed proportionally to all the participants in that epoch. When locking LP tokens in `TOLP`, the user can choose their own `_lockDuration`.

The `TOB` contract has 2 important functions. One is the `exitPosition`, which allows users to take out their TOLP token, and the other is the `exerciseOption` function, which allows the users to collect the option rewards. The issue is that the TOLP contract records lock duration in seconds, while the `TOB` contract processes them in epochs.

So if a user creates a lock position where the lock end time is a single second after the epoch change, the epoch when the lock is due to expire in the `TOB` contract will be calculated as shown.

```solidity
uint128 lockExpiry = lock.lockTime + lock.lockDuration;
uint256 lastEpoch = _timestampToWeek(lockExpiry);
```

So if a user lock expires a single second into an epoch, the `lastEpoch` will be calculated as that epoch and the user will be eligible for that entire epoch's rewards.

Moreover, this also allows a peculiar situation where a user can take out their TOLP token and exit their position and then come back and collect their token rewards. This is because when users want to exit their position, the contract checks if the lock has expired.

```solidity
if (!isSGLInRescueMode) {
    if (block.timestamp < lock.lockTime + lock.lockDuration) {
        revert LockNotExpired();
    }
}
```

But when a user wants to exercise their options, the contract checks for the liveness of the position in different terms, the epoch.

```solidity
uint256 expiryWeek = _timestampToWeek(_lock.lockTime + _lock.lockDuration);
isPositionActive = epoch <= expiryWeek;
```

The first method and the second method can disagree if a position is active. If the expiry time is in the middle of an epoch, for the entire second half of the epoch, the `exitPosition` function will treat the position as expired and will allow the user to take out their `TOLP` token, but the `exerciseOption` contract will treat the position as active and will allow the user to collect rewards as well. Due to the discussion above, the user can have only a single second of lock time remaining in this second epoch; so for the entire duration of 7 days, the user can have no `TOLP` locked in the contract but still be eligible to withdraw rewards.

### Proof of Concept

The situation can be created in the following manner:

1. Say the current timestamp is 100. Say the epoch is scheduled to end at 200. Alice creates a lock with the lock duration of 101 seconds.
2. The expiry epoch is calculated as 2, since epoch 1 ends at 200 but the position expires at 201.
3. Thus, Alice is eligible to collect rewards for epoch 2 even though she only spends 1 second in that epoch locked.
4. Alice can then take out her TOLP token the moment timestamp passes 201. However since the current epoch (2) is `<=` the expiry epoch (2), she can claim rewards later as well.
5. Alice waits until the next epoch start at 300 and claims her option rewards.

### Recommended Mitigation Steps

The different contracts should use the same mechanism to define locks. Either use epochs in both `TOLP` and `TOB` contracts, or use seconds in both. The current situation is a bit confusing and can lead to unexpected behavior.

### Assessed type

Invalid Validation

**[0xWeiss (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/131#issuecomment-2125602770)**

***

## [[M-13] Rescue request timestamp not reset in `TapiocaOptionLiquidityProvision.sol` contract](https://github.com/code-423n4/2024-02-tapioca-findings/issues/127)
*Submitted by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/127), also found by [immeas](https://github.com/code-423n4/2024-02-tapioca-findings/issues/177)*

### Impact

In order to put an asset in rescue mode, the admin first needs to call `requestSglPoolRescue`. This will start a cooldown period and the rescue can only be triggered after the cooldown period has passed. This is evident from the code in the `activateSglPoolRescue` function.

```solidity
if (block.timestamp < sglRescueRequest[sgl.sglAssetID] + rescueCooldown) revert RescueCooldownNotReached();
```

The issue is that once the rescue has been carried out, the value in `sglRescueRequest[sgl.sglAssetID]` is not reset. This means if the same asset is added back in, it will now not have any cooldown anymore. The contract will treat the asset as if the rescue request is still ongoing.

The `requestSglPoolRescue` cannot be called to reset the cooldown, since the value stored is non `0`. Since this bypasses a protection mechanism put in place by the devs, this is a medium severity issue.

### Proof of Concept

The problem arises when an asset is rescued, and then added back in. `sglRescueRequest[sgl.sglAssetID]` is left untouched, and so after being added back in it can be immediately rescued without any cooldown time.

### Recommended Mitigation Steps

Delete the entry in the `sglRescueRequest` mapping when the asset is rescued via the `activateSglPoolRescue` function.

**[0xRektora (Tapioca) confirmed, but disagreed with severity and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/127#issuecomment-2016851270):**
 > Informational.

***

## [[M-14] Options can be exercised preemptively due to timing delays](https://github.com/code-423n4/2024-02-tapioca-findings/issues/119)
*Submitted by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/119), also found by [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/188) and [deadrxsezzz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/35)*

When a user participates in the options system via `TapiocaOptionBroker.sol`, they mint an `otap` position in exchange for their `tolp` position. The time of creation is recorded, and the user is allowed to exercise the option only after a full epoch duration, which is a week.

```solidity
 if (block.timestamp < oTAPPosition.entry + EPOCH_DURATION) {
        revert OneEpochCooldown();
    }
```

The variable `netDepositedForEpoch` records how much liquidity the system expects to hold in any given epoch, and is used to calculate the rewards for the users. On calling `participate`, this variable is increased for the next epoch, and decreased on the expiration epoch.

```solidity
netDepositedForEpoch[epoch + 1][lock.sglAssetID] += int256(uint256(lock.ybShares));
netDepositedForEpoch[lastEpoch + 1][lock.sglAssetID] -= int256(uint256(lock.ybShares));
```

The issue is this accounting is done via `epoch`, while the cooldown is accounted via `block.timestamp`. So if a user participates at the very beginning of an epoch, their option will be exercisable after 7 days, which is very close to the time when the epoch number can be incremented. If the user is able to call `exerciseOption` before the epoch number is incremented, they can even participate in the current epoch! This is because the `epoch` number has not yet been updated, but the `EPOCH_DURATION` has already passed.

In this scenario, the user gets access to the rewards of the very same epoch they participated in, which should be impossible. They can also cause the contract to run out of rewards, as they are claiming rewards they shouldn't be owed. The contract calculates rewards based on the current net deposit, which hasn't been updated yet since the epoch number hasn't been updated yet.

```solidity
uint256 eligibleTapAmount = muldiv(tOLPLockPosition.ybShares, gaugeTotalForEpoch, netAmount);
eligibleTapAmount -= oTAPCalls[_oTAPTokenID][cachedEpoch];
```

Thus the user can take out rewards based on the wrong `netAmount`, which can lead to other users not getting their rewards, since the `eligibleAmount` is decreased by users not owed any rewards.

### Proof of Concept

The attack is carried out in the following steps. Lets assume the current epoch has JUST started, and is epoch 1. Let's assume the netAmount for this epoch is 100.

1. Alice calls `participate`. The `netAmount[2]` (next epoch) is increased by her deposit amount of 100.
2. Alice waits 1 week.
3. Alice then calls `exerciseOption`. Lets assume `newEpoch()` hasn't been called yet.
4. Alice passes the `OneEpochCooldown` check. Alice gets assigned rewards. Alice's rewards are = `100 * gaugeTotalForEpoch / netAmount[1], which is = 100 * total / 100 = total`.
5. The other depositors who hadn't collected their rewards yet cannot collect them anymore. This is because there are not enough tokens for the rewards anymore. This is because the contract used `netAmount[1]` as the denominator while there are more than `netAmount[1]` shareholders collecting rewards.

Since this allows users to collect rewards in the same epoch and break the accounting, and can be timed very effectively, this is a high severity issue.

### Recommended Mitigation Steps

The main issue is that the `OneEpochCooldown` is not measured in epochs and is measured in time instead, which will not necessarily always coincide. Can be fixed in a variety of methods:

1. Check `OneEpochCooldown` based on the epoch number, not the timestamp.
2. When calling `exerciseOption`, check if the epoch has completed. Similar to what is done in the `participate` function

```solidity
if (_timestampToWeek(block.timestamp) > epoch) revert AdvanceEpochFirst();
```

### Assessed type

Invalid Validation

**[0xRektora (Tapioca) confirmed via duplicate Issue #35](https://github.com/code-423n4/2024-02-tapioca-findings/issues/35#issuecomment-2016905538)**

**[LSDan (judge) decreased severity to Medium](https://github.com/code-423n4/2024-02-tapioca-findings/issues/119#issuecomment-2042891678)**

**[cryptotechmaker (Tapioca) commented via duplicate Issue #35](https://github.com/code-423n4/2024-02-tapioca-findings/issues/35#issuecomment-2039214790):**
> PR [here](https://github.com/Tapioca-DAO/tap-token/pull/180).

***

## [[M-15] `_internalRemoteTransferSendPacket()` can't send the difference back to the user](https://github.com/code-423n4/2024-02-tapioca-findings/issues/115)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/115), also found by [cccz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/29)*

In `TapiocaOmnichainReceiver`, when the user executes `MSG_REMOTE_TRANSFER`, if the `srcChain` amount request is bigger than the debited one, it overwrites the amount to credit with the amount debited and send the difference back to the user.

`lzCompose()` -> `_remoteTransferReceiver()` -> `_internalRemoteTransferSendPacket()`.

```solidity
    function _internalRemoteTransferSendPacket(
        address _srcChainSender,
        LZSendParam memory _lzSendParam,
        bytes memory _composeMsg
    ) internal returns (MessagingReceipt memory msgReceipt, OFTReceipt memory oftReceipt) {
...

        // If the srcChain amount request is bigger than the debited one, overwrite the amount to credit with the amount debited and send the difference back to the user.
        if (_lzSendParam.sendParam.amountLD > amountDebitedLD_) {
            // Overwrite the amount to credit with the amount debited
@>          _lzSendParam.sendParam.amountLD = amountDebitedLD_;
            _lzSendParam.sendParam.minAmountLD = amountDebitedLD_;
            // Send the difference back to the user
@>          _transfer(address(this), _srcChainSender, _lzSendParam.sendParam.amountLD - amountDebitedLD_);
        }
```

The above code, first modify `  _lzSendParam.sendParam.amountLD = amountDebitedLD_ `
Then call `  _transfer(address(this), _srcChainSender, _lzSendParam.sendParam.amountLD - amountDebitedLD_);`. This way the difference is always `0`.

Correctly `transfer()` the difference first, and then modify `_lzSendParam.sendParam.amountLD`.

### Impact

The difference token be left in the contract.

### Recommended Mitigation

```diff
    function _internalRemoteTransferSendPacket(
        address _srcChainSender,
        LZSendParam memory _lzSendParam,
        bytes memory _composeMsg
    ) internal returns (MessagingReceipt memory msgReceipt, OFTReceipt memory oftReceipt) {
...

        // If the srcChain amount request is bigger than the debited one, overwrite the amount to credit with the amount debited and send the difference back to the user.
        if (_lzSendParam.sendParam.amountLD > amountDebitedLD_) {
+          _transfer(address(this), _srcChainSender, _lzSendParam.sendParam.amountLD - amountDebitedLD_);
            // Overwrite the amount to credit with the amount debited
            _lzSendParam.sendParam.amountLD = amountDebitedLD_;
            _lzSendParam.sendParam.minAmountLD = amountDebitedLD_;
            // Send the difference back to the user
-           _transfer(address(this), _srcChainSender, _lzSendParam.sendParam.amountLD - amountDebitedLD_);
        }
```

### Assessed type

Context

**[LSDan (judge) decreased severity to Medium](https://github.com/code-423n4/2024-02-tapioca-findings/issues/115#issuecomment-2034024971)**

**[cryptotechmaker (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/115#issuecomment-2036634186):**
 > PR [here](https://github.com/Tapioca-DAO/tapioca-periph/commit/c9170340568a736c1acdb8ad82a1ef71e66165f0).

***

## [[M-16] `burst()` does not return eth when action fails](https://github.com/code-423n4/2024-02-tapioca-findings/issues/114)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/114), also found by [ronnyx2017](https://github.com/code-423n4/2024-02-tapioca-findings/issues/101), [rvierdiiev](https://github.com/code-423n4/2024-02-tapioca-findings/issues/61), and deadrxsezzz ([1](https://github.com/code-423n4/2024-02-tapioca-findings/issues/43), [2](https://github.com/code-423n4/2024-02-tapioca-findings/issues/42))*

When executing `Magnetar.burst()`, the user can specify `allowFailure = true`. If it fails, it ignores the current `_action` and execute another `_action`.

`burst()` -> `_executeCall(_allowFailure)`.

```solidity
    function _executeCall(address _target, bytes calldata _actionCalldata, uint256 _actionValue, bool _allowFailure)
        private
    {
        bool success;
        bytes memory returnData;

        if (_actionValue > 0) {
            (success, returnData) = _target.call{value: _actionValue}(_actionCalldata);
        } else {
            (success, returnData) = _target.call(_actionCalldata);
        }

@>      if (!success && !_allowFailure) {
            _getRevertMsg(returnData);
        }
    }
```

But with the current implementation, if the user also passes `_action.value> 0` and `_action.allowFailure = true`, if the action fails, the `_action.value` is not returned to the user, it stays in the contract.

Although the owner can retrieve the `eth` left in the contract via `rescueEth()`, the `eth` is not returned to the user until the owner executes `rescueEth()`. However, before the owner executes `rescueEth()`, a malicious user can use the contract's `eth` directly to execute an `action` .

For example, by using
`MagnetarAssetModule.depositRepayAndRemoveCollateralFromMarket()` -> `_withdrawToChain()` -> `_lzWithdraw()` -> `sendPacket{value:??} ()` to use up `eth`.

### Impact

If the `action` fails, the `eth` left in the contract can be stolen by malicious people.

### Recommended Mitigation

Recommends the final return of all `eth`:

```diff
    function burst(MagnetarCall[] calldata calls) external payable {
        uint256 valAccumulator;

        uint256 length = calls.length;

        for (uint256 i; i < length; i++) {
.....

        if (msg.value != valAccumulator) revert Magnetar_ValueMismatch(msg.value, valAccumulator);
+       if(address(this).balance>0){
+         msg.sender.call{value:address(this).balance}(""); // return all eth
+       }
      }
```

### Assessed type

Context

**[cryptotechmaker (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/114#issuecomment-2036678129):**
 > PR [here](https://github.com/Tapioca-DAO/tapioca-periph/commit/b6845e91e07937970dd1a7ba216fad95a4972c7d).

***

## [[M-17] After `unregisterSingularity()`, position has not been unlocked and will be locked in the contract](https://github.com/code-423n4/2024-02-tapioca-findings/issues/110)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/110), also found by [deadrxsezzz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/50) and [cccz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/30)*

When `singularity.rescue==true`, owner can execute `unregisterSingularity()`. This method will delete `activeSingularities[]/sglAssetIDToAddress[]`.

```solidity
    function unregisterSingularity(IERC20 singularity) external onlyOwner updateTotalSGLPoolWeights {
        uint256 sglAssetID = activeSingularities[singularity].sglAssetID;
        if (sglAssetID == 0) revert NotRegistered();
        if (!activeSingularities[singularity].rescue) revert NotInRescueMode();

        unchecked {
            uint256[] memory _singularities = singularities;
            uint256 sglLength = _singularities.length;
            uint256 sglLastIndex = sglLength - 1;

            for (uint256 i; i < sglLength; i++) {
                if (_singularities[i] == sglAssetID) {
                    // If in the middle, copy last element on deleted element, then pop
@>                  delete activeSingularities[singularity];
@>                  delete sglAssetIDToAddress[sglAssetID];

                    if (i != sglLastIndex) {
                        singularities[i] = _singularities[sglLastIndex];
                    }
                    singularities.pop();
                    emit UnregisterSingularity(address(singularity), sglAssetID);
                    break;
                }
            }
        }

        emit UnregisterSingularity(address(singularity), sglAssetID);
    }
```

However, this method does not determine whether there are still has locked positions. In this way, if the user wants to `unlock()`, it will not be executed and the `token` will be locked in the contract.

`activeSingularities[_singularity]` has been deleted.

```solidity
    function unlock(uint256 _tokenId, IERC20 _singularity, address _to) external {
...
@>      SingularityPool memory sgl = activeSingularities[_singularity];

        yieldBox.transfer(address(this), _to, lockPosition.sglAssetID, lockPosition.ybShares);
@>      activeSingularities[_singularity].totalDeposited -= lockPosition.ybShares;

        emit Burn(_to, lockPosition.sglAssetID, _tokenId);
    }
```

### Recommended Mitigation

```diff
    function unregisterSingularity(IERC20 singularity) external onlyOwner updateTotalSGLPoolWeights {
...
            for (uint256 i; i < sglLength; i++) {
                if (_singularities[i] == sglAssetID) {
+                   //check totalDeposited
+                   require(activeSingularities[singularity].totalDeposited == 0 , "invalid");

                    // If in the middle, copy last element on deleted element, then pop
                    delete activeSingularities[singularity];
                    delete sglAssetIDToAddress[sglAssetID];

                    if (i != sglLastIndex) {
                        singularities[i] = _singularities[sglLastIndex];
                    }
                    singularities.pop();
                    emit UnregisterSingularity(address(singularity), sglAssetID);
                    break;
                }
            }
        }
```

### Assessed type

Context

**[cryptotechmaker (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/110#issuecomment-2037062216):**
 > PR [here](https://github.com/Tapioca-DAO/tap-token/pull/177).

**[0xRektora (Tapioca) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/110#issuecomment-2053744605):**
 > @LSDan, This one should be QA. 
> 
> Although it makes sense to add this change, but there'll never realistically be `0` total deposited in a pool, leaving some dust. Furthermore, it opens up an attack vector to DoS this functionality. I'd say it's the responsibility of the DAO to make sane decision about when to unregister the pool. There's already a 2 day cooldown period as a safeguard.

***

## [[M-18] `TapiocaOptionBroker.participate()` with the approve authorization, it still cannot be executed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/109)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/109), also found by [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/123) and [cccz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/28)*

If the user `isApproved()`, the user can call `TapiocaOptionBroker.participate()`.
The code is as follows:

```solidity
    function participate(uint256 _tOLPTokenID) external whenNotPaused nonReentrant returns (uint256 oTAPTokenID) {
...

        TWAMLPool memory pool = twAML[lock.sglAssetID];
        if (pool.cumulative == 0) {
            pool.cumulative = EPOCH_DURATION;
        }

@>      if (!tOLP.isApprovedOrOwner(msg.sender, _tOLPTokenID)) {
            revert NotAuthorized();
        }

       {
@>        bool isErr = pearlmit.transferFromERC721(msg.sender, address(this), address(tOLP), _tOLPTokenID);
            if (isErr) revert TransferFailed();
        }
```

However, in the current implementation, even though `msg.sender` has obtained authorization (`isApprovedOrOwner(msg.sender) == true`), it is still unable to execute due to the incorrect usage of: `pearlmit.transferFromERC721(msg.sender, address(this), address(tOLP), _tOLPTokenID);`
Passing `msg.sender` as the `owner` will result in failure to execute.

`pearlmit.transferFromERC721(msg.sener,to)` -> `IERC721(token).transferFrom(owner, to)` -> `_transfer(owner,to)` -> `require(ERC721.ownerOf(tokenId) == owner`.

It will check the first parameter is the owner of NFT. It should use: `pearlmit.transferFromERC721(tOLP.ownerOf(_tOLPTokenID), address(this), address(tOLP), _tOLPTokenID)`.

### Impact

Although `msg.sender` has been granted authorization, it is still unable to execute `participate()`.

### Recommended Mitigation

```diff
    function participate(uint256 _tOLPTokenID) external whenNotPaused nonReentrant returns (uint256 oTAPTokenID) {
...

        if (!tOLP.isApprovedOrOwner(msg.sender, _tOLPTokenID)) {
            revert NotAuthorized();
        }

        // Transfer tOLP position to this contract
        // tOLP.transferFrom(msg.sender, address(this), _tOLPTokenID);
        {
-           bool isErr = pearlmit.transferFromERC721(msg.sender, address(this), address(tOLP), _tOLPTokenID);
+           bool isErr = pearlmit.transferFromERC721(tOLP.ownerOf(_tOLPTokenID), address(this), address(tOLP), _tOLPTokenID); 
            if (isErr) revert TransferFailed();
        }
```

### Assessed type

Context

**[0xRektora (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/109#issuecomment-2016846705)**

**[cryptotechmaker (Tapioca) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/109#issuecomment-2037122754):**
 > PR [here](https://github.com/Tapioca-DAO/tap-token/pull/178).

***

## [[M-19] Adding reward tokens to `twTap` could cause pending cross-chain claim rewards msg to be stuck](https://github.com/code-423n4/2024-02-tapioca-findings/issues/102)
*Submitted by [ronnyx2017](https://github.com/code-423n4/2024-02-tapioca-findings/issues/102)*

There is a check in the `TapTokenReceiver._claimTwpTapRewardsReceiver` to ensure the claimed types amount is equal to the token types amount of `sendParam`.

```solidity
        if (
            (claimedAmount_.length - 1) // Remove 1 because the first index doesn't count.
                != claimTwTapRewardsMsg_.sendParam.length
        ) {
            revert
```

The process of cross-chain claim is as follows:
The B chain is the main chain, which the `twTap` is deployed. And the user is on the chain A.

1. The user calls `TapOFT.sendPacket` with `MSG_CLAIM_REWARDS` message on the chain A.
2. The LZ replays the message on the chain B, which will call the `TapTokenReceiver._claimTwpTapRewardsReceiver` function.
3. `TapTokenReceiver._claimTwpTapRewardsReceiver` function will send every reward token to the chain A by LZ `TapTokenSender(rewardToken_).sendPacket`.

### Proof of Concept

The issue is that, if after step 1 the LZ message sent, a new reward token is added to the `twTAP` on the chain B, then step 2 will be revert in the `TapTokenReceiver._claimTwpTapRewardsReceiver` function. So this message will be stuck in the LZ indefinitely.

### Impact

Every LZ message sent by `TapToken.sendPacket` can carry cross-chain TAP tokens, which means the `amountToSendLD` of the message is not zero. It will burn the TAP token of the source chain and mint them on the target chain. If the message is stuck, these TAP token will be lost forever.

### Assessed type

Context

**[0xWeiss (Tapioca) disputed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/102#issuecomment-2125605447)**

*Note: For full discussion, see [here](https://github.com/code-423n4/2024-02-tapioca-findings/issues/102).*

***

## [[M-20] Max magnitude lock check will lead to a DoS and possible monopolization of `gov/Option` on `twTAP`/`TapiocaOptionBroker`](https://github.com/code-423n4/2024-02-tapioca-findings/issues/98)
*Submitted by [ronnyx2017](https://github.com/code-423n4/2024-02-tapioca-findings/issues/98)*

<https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/governance/twTAP.sol#L315>

<https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/options/TapiocaOptionBroker.sol#L261>

### Vulnerability details

There is a max magnitude lock check in the `twTAP.participate` function, it can't be greater than 4x the cumulative:

        if (magnitude >= pool.cumulative * 4) revert NotValid();

Because the param `_duration` can't be less than `EPOCH_DURATION = 7 days = 604800`, lets assume `pool.cumulative` is x, and solve for its minimum value without DoS:

    (604800 * 604800 + x * x)**0.5 - x < 4 * x

Solution derived: `the x, pool.cumulative, must be >= 123455`.

The main issue is that, when a user participates the lock with `divergenceForce = false`, his participation will decrease `pool.cumulative`. Meanwhile, if there are positions previously entered with `divergenceForce = true` that are now exiting, then `pool.cumulative` will be reduced to below 123455.

### Impact

TAP cannot be staked until `pool.cumulative` rises to 123455, and the system will remain under the DoS for even months until positions with `divergenceForce = false` can exit (arrive at the unlocking time). During this DoS period, the attacker has the potential to monopolize gov.

The same issue is also in the `TapiocaOptionBroker`. The following PoC uses the `twTap` as the exploit case.

### Proof of Concept

Flow of attack:

1. The user1 locked some  (with `hasVotingPower = true`) for a duration = 1004800 (11.6 days).
2. After 11.6 days and before the user1 unlocks, the user2 lock some TAP (with `hasVotingPower = true`) for a duration = 1172776 (13.5 days).
3. The user1 unlocks his `twTap` position.
4. After this unlocking, the `pool.cumulative` will be 77922, which is `<` 123455.

So the `twTAP` will be DoS until the user2 (attacker) unlocks, which has to wait about 13.5 days. During this DoS period, the attacker is the only voter of the gov, the attack could have complete control of gov.

```
def computeMagnitude(_duration, cumulative):
    return int((_duration**2 + cumulative**2)**0.5) - cumulative

def assetValid4(_magnitude, _cumulative, tag):
    # print(_magnitude, _cumulative * 4)
    assert _magnitude < _cumulative * 4, f"Not Valid here #{tag}"

def update(_duration, _averageMagnitude, _cumulative, _NO):
    print(f"======{_NO}======")
    magnitude0 = computeMagnitude(_duration, _cumulative)
    print("duration, cumulative_before", _duration, _cumulative)
    assetValid4(magnitude0, _cumulative, _NO)
    _averageMagnitude = int((_averageMagnitude + magnitude0) / _NO)
    if _duration >= _cumulative:
        print("cumulative_delta", _averageMagnitude)
        _cumulative += _averageMagnitude
    else:
        print("cumulative_delta", -_averageMagnitude)
        _cumulative -= _averageMagnitude
    print("averageMagnitude,cumulative_after", _averageMagnitude, _cumulative)
    return _averageMagnitude, _cumulative

def main():
    averageMagnitude = 0
    cumulative = 7 * 24 * 3600
    # 1
    NO = 1
    duration0 = 1004800
    averageMagnitude, cumulative = update(duration0, averageMagnitude, cumulative, NO)
    cache_c_delta0 = averageMagnitude
    
    # 2 
    NO += 1
    duration1 = 1172776
    averageMagnitude, cumulative = update(duration1, averageMagnitude, cumulative, NO)

    # after #1 unlock
    # pool.cumulative -= #1.averageMagnitude
    print("=================")
    cumulative_after_unlock = cumulative - cache_c_delta0
    print(cumulative_after_unlock, cumulative_after_unlock <= 123454)
    
main()
```

The above py script simulates the math process of the attack, print log:

    ╰─ python3 cumulative.py
    ======1======
    duration, cumulative_before 1004800 604800
    cumulative_delta 567977
    averageMagnitude,cumulative_after 567977 1172777
    ======2======
    duration, cumulative_before 1172776 1172777
    cumulative_delta -526878
    averageMagnitude,cumulative_after 526878 645899
    =================
    77922 True

### Recommendation

Set the minimum threshold for the check, such as 7 days; if the duration meets `EPOCH_DURATION <= duration <= minimum threshold || magnitude < pool.cumulative * 4`, then lock-in is permitted.

### Assessed type

Context

**[0xWeiss (Tapioca) acknowledged](https://github.com/code-423n4/2024-02-tapioca-findings/issues/98#issuecomment-2125608685)**

*Note: For full discussion, see [here](https://github.com/code-423n4/2024-02-tapioca-findings/issues/98).*

***

## [[M-21] Gov (`twTAP`) and Tapioca Option can be monopolized by an attacker](https://github.com/code-423n4/2024-02-tapioca-findings/issues/97)
*Submitted by [ronnyx2017](https://github.com/code-423n4/2024-02-tapioca-findings/issues/97), also found by [immeas](https://github.com/code-423n4/2024-02-tapioca-findings/issues/165) and [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/55)*

<https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/governance/twTAP.sol#L592-L594>

### Vulnerability details

The function `twTAP._releaseTap` updates only `--twAML.totalParticipants` and neglected to update `twAML.averageMagnitude`. This will result in `twAML.averageMagnitude` accumulating every time a new position participates, without ever decreasing.

```solidity
            pool.averageMagnitude = (pool.averageMagnitude + magnitude) / pool.totalParticipants; // compute new average magnitude
```

### Impact

An attacker can monopolize the gov by precisely controlling the number of tokens entering and exiting to ensure that only their own position remains in the current `twTap`.

On the other hand, there is another exploit way here. If `pool.cumulative < pool.averageMagnitude`, then `pool.cumulative` will be set to `0`. But the greater `position.averageMagnitude` will be added to `pool.cumulative` when the position exits. This will cause `pool.cumulative` to continuously increase,  which will result in the efficiency of `twTAP`/`TapiocaOptionBroker` becoming increasingly lower. Because the `multiplier` of the `twTAP` or `target` of the `TapiocaOptionBroker` will always be `dMIN`.

The same issue is also in the `TapiocaOptionBroker`. The only difference is that the `pool.cumulative` can't be decreased to zero, because it will be reset to `EPOCH_DURATION` if it's zero [here](<https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/options/TapiocaOptionBroker.sol#L242-L244>). The following PoC uses the `twTap` as the exploit case.

### Proof of Concept

We describe this attack using the simplest scenario, assuming that initially, the pool contains only the attacker's own position, but the `pool.averageMagnitude` is not zero (which means there were some participators before).

1. The attacker first needs to create a positions with `divergenceForce = true`, and `magnitude = M1 = current pool.averageMagnitude`. After the participation, the `pool.averageMagnitude` will be `pool.averageMagnitude + M1`.
2. Waiting for the unlock time and exits the above position. After the exit, pool.`averageMagnitude` remains unchanged (`pool.averageMagnitude +M1`), but the `pool.totalParticipants` is back to `0`.
3. The attacker repeats the above process, which results in `pool.averageMagnitude` increasing by `M1` each time.
4. Before the last unlock, the `pool.cumulative` and `pool.averageMagnitude` now are very large values, the attacker participates  with `divergenceForce = false` for a couple of months.
5. Then the attacker exits his last position with `divergenceForce = true`. It will make `pool.cumulative = 0;`, which breaks the developers' assumptions about this branch:

<https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/governance/twTAP.sol#L331-L336>

```solidity
                // TODO: Strongly suspect this is never less. Prove it.
                if (pool.cumulative > pool.averageMagnitude) {
                    pool.cumulative -= pool.averageMagnitude;
                } else {
                    pool.cumulative = 0;
                }
```

Now others will no longer be able to participate in `twTAP`, and the gov will be monopolized by the attacker.

Please note that "the pool contains only the attacker's own position" is not a necessary condition; the attack can still be carried out even with the participation of others. As the exit process accumulates, this attack will become increasingly easier to occur, and may even be triggered unintentionally by users.

### Recommendation

Update `pool.averageMagnitude` in the `_releaseTap`.

### Assessed type

Context

**[LSDan (judge) decreased severity to Medium](https://github.com/code-423n4/2024-02-tapioca-findings/issues/97#issuecomment-2042889818)**

**[0xRektora (Tapioca) confirmed, but disagreed with severity and commented via duplicate Issue #165](https://github.com/code-423n4/2024-02-tapioca-findings/issues/165#issuecomment-2016877257):**
> Low. While true, the probabilities of this happening are very thin.

*Note: For full discussion, see [here](https://github.com/code-423n4/2024-02-tapioca-findings/issues/97).*

***

## [[M-22] `MagnetarHelper.getFractionForAmount` uses the wrong rounding and will yield the wrong result](https://github.com/code-423n4/2024-02-tapioca-findings/issues/94)
*Submitted by [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/94), also found by [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/90)*

`MagnetarHelper.getFractionForAmount` is used to determine the `fraction` (shares) that will be received when an `amount` is deposited. The code needs to compute the `totalShares` and then determine what the fraction is going to be.

The logic is used in `Singularity._removeAsset` and since it's tied to a withdrawal, the rounding will be `down`. However, in `MagnetarHelper` the round is `up`.

<https://github.com/Tapioca-DAO/tapioca-periph/blob/2ddbcb1cde03b548e13421b2dba66435d2ac8eb5/contracts/Magnetar/MagnetarHelper.sol#L208-L219>

```solidity
    function getFractionForAmount(ISingularity singularity, uint256 amount) external view returns (uint256 fraction) {
        (uint128 totalAssetShare, uint128 totalAssetBase) = singularity.totalAsset();
        (uint128 totalBorrowElastic,) = singularity.totalBorrow();
        uint256 assetId = singularity.assetId();

        IYieldBox yieldBox = IYieldBox(singularity.yieldBox());

        uint256 share = yieldBox.toShare(assetId, amount, false);
        uint256 allShare = totalAssetShare + yieldBox.toShare(assetId, totalBorrowElastic, true); /// @audit Round UP for Debt

        fraction = allShare == 0 ? share : (share * totalAssetBase) / allShare;
    }
```

See the actual implementation in `Singularity`:

<https://github.com/Tapioca-DAO/Tapioca-bar/blob/c2031ac2e2667ac8f9ac48eaedae3dd52abef559/contracts/markets/singularity/SGLCommon.sol#L199-L216>

```solidity
    function _removeAsset(address from, address to, uint256 fraction) internal returns (uint256 share) {
        if (totalAsset.base == 0) {
            return 0;
        }
        Rebase memory _totalAsset = totalAsset;
        uint256 allShare = _totalAsset.elastic + yieldBox.toShare(assetId, totalBorrow.elastic, false);
        share = (fraction * allShare) / _totalAsset.base;
    }
```

This will cause issues when calculating how much fraction to withdraw based on the amount required by the withdrawer.

### Mitigation

Change the rounding direction:

```solidity
        uint256 allShare = totalAssetShare + yieldBox.toShare(assetId, totalBorrowElastic, down);
```

### Assessed type

Math

**[cryptotechmaker (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/94#issuecomment-2037278183):**
 > PR [here](https://github.com/Tapioca-DAO/tapioca-periph/commit/a458eaf5771ca9bb29ba18f4f90205d6bcf6fb79).

***

## [[M-23] Sending more TAP tokens to the `TapToken.sol` contract does not actually increase the total amount to be distributed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/84)
*Submitted by [deadrxsezzz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/84)*

Within the `TapToken` contract, the to-be-distributed balance is tracked by the `dso_supply`. Every week a percentage of is distributed to the users via `oTAP` emissions.

```solidity
    function emitForWeek() external onlyMinter returns (uint256) {
        if (_getChainId() != governanceEid) revert NotValid();

        uint256 week = _timestampToWeek(block.timestamp);
        if (emissionForWeek[week] > 0) return 0;

        // Compute unclaimed emission from last week and add it to the current week emission
        uint256 unclaimed;
        if (week > 0) {
            // Update DSO supply from last minted emissions
            dso_supply -= mintedInWeek[week - 1];

            // Push unclaimed emission from last week to the current week
            unclaimed = emissionForWeek[week - 1] - mintedInWeek[week - 1];
        }
        uint256 emission = _computeEmission();
        emission += unclaimed;

        // Boosted TAP is burned and added to the emission to be minted on demand later on in `extractTAP()`
        uint256 boostedTAP = balanceOf(address(this));
        if (boostedTAP > 0) {
            _burn(address(this), boostedTAP);
            emission += boostedTAP; // Add TAP in the contract as boosted TAP
            emit BoostedTAP(boostedTAP);
        }

        emissionForWeek[week] = emission;
        emit Emitted(week, emission);

        return emission;
    }
```

If we look at the code, we'll see that there's a check if there's extra tokens within the contract and distribute them if that's the case. The problem is that if such funds are distributed, they'll still be deducted from the `dso_supply` which will mean that these tokens will not be treated as an extra.

What they'll do is actually speed up the regular distribution and break the linearly decaying curve of weekly emissions.

Note: From the same core of the problem, there could be an underflow in `dso_supply` (if there's enough Boost Tap sent when the weekly emissions have become low enough). This would block rolling over a week, within the `TapToken` and `TapiocaOptionBroker` contracts, though no funds will be locked.

### Recommended Mitigation Steps

Fix accounting for extra tap tokens sent.

### Assessed type

Context

**[0xRektora (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/84#issuecomment-2016834742):**
 > Nice catch, `mintedInWeek` is increased in `extractTAP()`. If boosted with `TAP` sent from outside the DSO it actually reduces its supply.

***

## [[M-24] Unordered Nonces open up to further MEV risks](https://github.com/code-423n4/2024-02-tapioca-findings/issues/82)
*Submitted by [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/82)*

While a great effort was made to mitigate out of order nonce execution, the reality is that since `PermitC` allows unordered nonces, then nonces could be executed out of order. This opens up more problems than the original Permit Exploit. The original Permit exploit allowed to effectively always make multi-operations revert. This new scenario instead allows to use the order of nonces that will cause the most damage.

The most basic example would be using the reverse order to keep allowances to be non-zero. This may open up to more exploits, an example being claiming `TAP`, `twTAP` or rewards to router addresses by keeping the allowance as non-zero. Additionally, any time more than one Permit is issued, a race condition is available. This race condition would allow an exploiter to consume the nonces out of order, and then causes the transaction to revert. This, in contrast to the previous iteration, allows all possible sequences of combinations of allowances to determine the final result, while the original permit operation would allow only the proper sequence to be executed (with pauses between each step).

This additional risk can create scenarios in which outstanding allowance is left, which could incorrectly signal the willingness to claim tokens or the willingness to allow a target to bridge funds at a different time than intended. It's worth reiterating how `Signatures` can be executed as soon as made available on any mempool, whether a L2 or LayerZeros system.

### POC

- Victim signs Permit A, B and C.
- Notice how any of the permutations of `[A, B, C]` could be used out of order.
- Front-runner will execute those signatures at whichever order is best for them to leak the most value.

### Mitigation

The only solution I have found is to ensure that all "Macros" in Magnetar always approve a specific contract at most once. Revokes are done without signatures, either by consuming the allowance via a `transferFrom` (which may not be possible) or by introducing a function that allows an operator to reset their allowance.

### Assessed type

MEV

**[0xRektora (Tapioca) acknowledged and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/82#issuecomment-2016832977):**
 > If I remember correctly, the team from Limit Break did not build `PermitC` to have batched transaction, but it can be dangerous if implemented wrong. Will forward the message.
>
> As for Tapioca, we do have a batch function in [`Pearlmit`](https://github.com/Tapioca-DAO/tapioca-periph/blob/main/contracts/pearlmit/Pearlmit.sol#L78) that will force the signatures to be verified against the order they were sent to.
>
> We believe the solution to the griefing scenario would be to use something like [`permitTransferFromWithAdditionalDataERC20`](https://github.com/limitbreakinc/PermitC/blob/c431dc5e80690c1d8c3727f5992d519df3d38254/src/PermitC.sol#L523) on said batch, by effectively binding the whole Tx (approvals paired with compose messages) and force the approval to be executed only in the case, which would nullify the front-running  incentives.

**[0xRektora (Tapioca) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/82#issuecomment-2016902846):**
 > Limit Break answer -- 
> 
> >Yes - as designed it's explicitly allowed to use unordered nonces, so this would be valid.
> A modification could be made to the `_checkAndInvalidateNonce` function if you want to do ordered where you have a tracker by account and make sure that `nonce == nextNonce[owner]`
> but we don't want that for our base case as unordered nonces are required to execute orders out of sequence.

***

## [[M-25] Same contract multi permits fundamentally cannot be solved via the chosen standards](https://github.com/code-423n4/2024-02-tapioca-findings/issues/81)
*Submitted by [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/81), also found by GalloDaSballo ([1](https://github.com/code-423n4/2024-02-tapioca-findings/issues/83), [2](https://github.com/code-423n4/2024-02-tapioca-findings/issues/67)), [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/151), [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/134), [bin2chen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/104), and [cccz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/36)*

The finding is a direct follow up to: `All cross-chain USDO and TOFT flows using approvals may be susceptible to permit-based DoS griefing` from the Spearbit report.

Since permits are signatures, they will be available to anyone monitoring the chain. They will be usable by anyone, since the goal of permit is allowing some other `msg.sender` to broadcast the signature and have it work.

### POC

Due to this, the current architecture is still subject to front-run exploits via the following:

- Monitor the mempool for any sequence of permit signatures.
- Execute all of the signatures before the transaction.

Any time, more than one permit is signed to the same token, for example, to Add Exact Allowance and Revoke it, front-running the calls will burn the approvals and reset the allowance down to `0`.

The transaction, which may have worked had only one of the signatures been front-run, is unable to function as the last signature for revoking will be broadcasted right after the first one. This effectively means that the only architecture that could be used for Tapioca is single signature, with no revokes, which doesn't seem to be the case at this time.

### Mitigation

The only solution I have found at this time would be to use Permits to grant approvals (with try-catch) and not using permits to revoke approvals, as the revoke permit call could be front-run causing all `xChain` calls to revert.

If you wish to use exact approvals `xChain`(which I recommend), you'd have to solve for rounding errors when converting shares vs amounts. Due to this, you may recommend people to grant higher allowances, and then change all `toft` tokens to have a `renounceAllowance` function, which would re-set the allowance on behalf of the operator, enforcing a strict `0 -> X -> 0` allowance pattern while avoiding front-run griefs.

This would ensure that trusted Tapioca Operators receive allowances, and re-set them at the end of all of their operations, which gives a stronger security guarantee. We built something similar for eBTC, with PositionMangers [here](<https://github.com/ebtc-protocol/ebtc/blob/3406f0d88ac9935da53f7371fb078d11c066802e/packages/contracts/contracts/Interfaces/IPositionManagers.sol#L30>).

### Assessed type

MEV

**[cryptotechmaker (Tapioca) confirmed and commented via duplicate Issue #83](https://github.com/code-423n4/2024-02-tapioca-findings/issues/83#issuecomment-2039105724):**
> PR [here](https://github.com/Tapioca-DAO/tap-yieldbox/pull/4).

***

## [[M-26] Incorrect decoding in `decodeLockTwpTapDstMsg`](https://github.com/code-423n4/2024-02-tapioca-findings/issues/69)
*Submitted by [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/69), also found by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/144)*

The decoding applied in `decodeLockTwpTapDstMsg` is incorrect as there are more than one combination of bytes that would result in the same result.

This is due to:
`uint96 duration = BytesLib.toUint96(BytesLib.slice(_msg, userOffset_, durationOffset_), 0);` , which uses length `== durationOffset_` which is 32 instead of 12.

`uint256 amount = BytesLib.toUint256(BytesLib.slice(_msg, durationOffset_, _msg.length - durationOffset_), 0);` uses the length of the message, instead of 32 which would be the maximum size of a u256.

### POC

This was found with Medusa, using Recon.

The test is as follows:

```solidity
    function malformedTokenTwTapPositionMsg(bytes memory encoded) public {
        LockTwTapPositionMsg memory decoded = TapTokenCodec.decodeLockTwpTapDstMsg(encoded);
        bytes memory ReEncoded = TapTokenCodec.buildLockTwTapPositionMsg(decoded);

        emit DebugBytes(encoded);
        emit DebugBytes(ReEncoded);
        t(BytesLib.equal(encoded, ReEncoded), "tokenTwTapPositionMsg");
    }
```

And a repro case is:

```solidity
function test_malformedTokenTwTapPositionMsg_codec() public {
    malformedTokenTwTapPositionMsg(624640ab9f2104f27610f40e02a5184fc6e28e66473292539dccd55a499f6ce9e6103ab8afd0ef7ebd66e9b36707fb0a70bd2db5189ae20d11df6743e19fd653638b193c3e611e038a16fcc61179eebc1d4c);
}
```

### Mitigation

Change:

`uint96 duration = BytesLib.toUint96(BytesLib.slice(_msg, userOffset_, durationOffset_), 0);`

to

`uint96 duration = BytesLib.toUint96(BytesLib.slice(_msg, userOffset_, 12), 0);`, which will prevent reading the wrong area of memory.

Change:

`uint256 amount = BytesLib.toUint256(BytesLib.slice(_msg, durationOffset_, _msg.length - durationOffset_), 0);`

to

`uint256 amount = BytesLib.toUint256(BytesLib.slice(_msg, durationOffset_, 32), 0);`, which will ensure that the bytes being read are the length of the message, instead of 32 which would be the maximum size of a u256.

### Assessed type

en/de-code

**[cryptotechmaker (Tapioca) confirmed via duplicate Issue #144](https://github.com/code-423n4/2024-02-tapioca-findings/issues/144#issuecomment-2011700124)**

***

## [[M-27] Cross chain messages in `MagnetarAssetXChainModule` and `MagnetarMintXChainModule` will not work](https://github.com/code-423n4/2024-02-tapioca-findings/issues/62)
*Submitted by [rvierdiiev](https://github.com/code-423n4/2024-02-tapioca-findings/issues/62), also found by [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/155)*

In order to send LZ message `MagnetarBaseModule._withdrawToChain` function is called. This function allows to include composed message only [if `data.unwrap` is set to true](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarBaseModule.sol#L71-L81). In this case `_lzCustomWithdraw` function will be used, which [will include composed message](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarBaseModule.sol#L155).

In case if `!data.unwrap`, then `_lzWithdraw` function is called, which [calls `_prepareLzSend` function](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarBaseModule.sol#L120), which includes empty composed message. If you want to include composed message, then you should set `data.unwrap` as true.

Now, let's look into `MagnetarMintXChainModule.mintBBLendXChainSGL` function, which [passes false](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarMintXChainModule.sol#L86). Then look into `MagnetarAssetXChainModule.depositYBLendSGLLockXchainTOLP` function, which [passes false](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarAssetXChainModule.sol#L104).

As both of them pass `data.unwrap` as false, it means that compose message will not be crafted and this cross chain functionality will not work.

### Impact

It will be not possible to min `usdo` on one chain and lend it to singularity on another chain.

### Tools Used

VsCode

### Recommended Mitigation Steps

Pass ``data.unwrap` as true.

### Assessed type

Error

**[cryptotechmaker (Tapioca) confirmed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/62#issuecomment-2058663107):**
 > PR [here](https://github.com/Tapioca-DAO/tapioca-periph/pull/234/commits/e08f90070e35d7b08331909e1fcde279fe1ebc10).
> 

***

## [[M-28] `MagnetarMintXChainModule` will not work as msg type is not allowed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/59)
*Submitted by [rvierdiiev](https://github.com/code-423n4/2024-02-tapioca-findings/issues/59)*

Users can mint `USDO` on chain A, then lend this `USDO` to singularity on chain B and lock singularity tokens to be able to get tap options on chain C.

The first step of this flow is inside `MagnetarMintXChainModule.mintBBLendXChainSGL` function. This function [mints `USDO`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarMintXChainModule.sol#L67-L69) and then [initiates LZ message to chain B](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarMintXChainModule.sol#L82-L96) to process second step using `_withdrawToChain` function.

When message will be received by `USDO` on chain B, then receiver will handle compose message [and `MSG_DEPOSIT_LEND_AND_SEND_FOR_LOCK` msg type should be provided to process it correctly](https://github.com/Tapioca-DAO/Tapioca-bar/blob/c2031ac2e2667ac8f9ac48eaedae3dd52abef559/contracts/usdo/modules/UsdoReceiver.sol#L88-L95). The problem is that `USDO` will never receive such msg type as it is not allowed.

Let's check how `_withdrawToChain` function works on chain A. In order to request compose message [it should call `_lzCustomWithdraw`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarBaseModule.sol#L72-L80). This function then [creates instance of `TapiocaOmnichainEngineHelper` contract](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarBaseModule.sol#L142), which will be used to prepare LZ message.

When `TapiocaOmnichainEngineHelper` [will build compose message](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/extension/TapiocaOmnichainEngineHelper.sol#L141-L149) it [will call `_sanitizeMsgType` function](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/extension/TapiocaOmnichainEngineHelper.sol#L316) with msg type that is going to be sent.

<https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/extension/TapiocaOmnichainEngineHelper.sol#L333-L346>

```solidity
    function _sanitizeMsgType(uint16 _msgType) internal pure {
        if (
            // LZ
            _msgType == MSG_SEND
            // Tapioca msg types
            || _msgType == MSG_APPROVALS || _msgType == MSG_NFT_APPROVALS || _msgType == MSG_PEARLMIT_APPROVAL
                || _msgType == MSG_REMOTE_TRANSFER || _msgType == MSG_YB_APPROVE_ASSET || _msgType == MSG_YB_APPROVE_ALL
                || _msgType == MSG_MARKET_PERMIT
        ) {
            return;
        } else if (!_sanitizeMsgTypeExtended(_msgType)) {
            revert InvalidMsgType(_msgType);
        }
    }
```

As you can see this function allows only some types and other should be handled by `_sanitizeMsgTypeExtended` function and this function [is empty](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/extension/TapiocaOmnichainEngineHelper.sol#L351) and returns false. It is designed to be extended by other helpers, such as [`UsdoHelper`](https://github.com/Tapioca-DAO/Tapioca-bar/blob/c2031ac2e2667ac8f9ac48eaedae3dd52abef559/contracts/usdo/extensions/UsdoHelper.sol#L62-L69).

But as `_lzCustomWithdraw` always creates instance of `TapiocaOmnichainEngineHelper` it means that some messages will be not allowed and will not work. Thus, whole minting flow that I have described on the beginning won't work.

### Impact

Users can't mint on one chain and deposit on another.

### Tools Used

VsCode

### Recommended Mitigation Steps

For different `oft` token you should use different helper. For example, if message is going to be sent to `USDO`, then `UsdoHelper` should be used; if message comes to `tOft`, then ToftHelper is needed.

Or you can set all approved messaged in `TapiocaOmnichainEngineHelper` instead, then you can leave current design of `MagnetarBaseModule`.

### Assessed type

Error

**[cryptotechmaker (Tapioca) disputed and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/59#issuecomment-2012816824):**
 > Invalid. The following extends the default behavior, see [here](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/TapiocaOmnichainReceiver.sol#L174).


**[rvierdiiev (warden) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/59#issuecomment-2051233203):**
 > Sponsor said that issue is invalid, because `TapiocaOmnichainReceiver` has `_toeComposeReceiver` function to handle this. This is incorrect.
> 
> `TapiocaOmnichainReceiver.sol` is the contract that is responsible for receiving message on another chain. But in this issue I have described the fact that initiating of request on source chain will fail, so destination chain and `TapiocaOmnichainReceiver` will not even receive it, because the source chain will not allow to send such message.
> 
> I ask the judge and sponsor to go through the issue one more time with the whole message flow that I have described to see, that call will not be executed.

***

## [[M-29] `AirdropBroker`: Airdrops in epoch 4 can participate and exercise options in subsequent epochs](https://github.com/code-423n4/2024-02-tapioca-findings/issues/21)
*Submitted by [cccz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/21)*

In `AirdropBroker`, the owner calls `registerUsersForPhase` with `_phase = 4` to airdrop to users in epoch 4 to 8.

```solidity
        else if (_phase == 4) {
            for (uint256 i; i < _users.length; i++) {
                phase4Users[_users[i]] = _amounts[i];
            }
        }
```

And the documentation says:

> Phase Four will have five sub phases, each bearing one week epochs. Four of the sub phases will be rewarded to `twTAP` lockers each weekly epoch over four weeks. Unclaimed `aoTAP` in each epoch will roll over to the next epoch, until the final sub phase.

The problem here is that `phase4Users` is not cleared before the start of the 5 sub-phases of phase 4, which results in users being able to participate and exercise the epoch 4 options in epoch 5.

```solidity
        } else if (cachedEpoch >= 4) {
            aoTAPTokenID = _participatePhase4();
        }
...
    function _participatePhase4() internal returns (uint256 oTAPTokenID) {
        uint256 _eligibleAmount = phase4Users[msg.sender];
        if (_eligibleAmount == 0) revert NotEligible();

        // Close eligibility
        phase4Users[msg.sender] = 0;

```

Consider the following scenario. There are 10,000 `aoTAPs` in phase 4, which means that epoch 4, 5, 6, and 7 will receive 2,500 `aoTAPs` respectively, and the remaining unclaimed `aoTAPs` will be rolled over to the next epoch.

- In epoch 4, Alice received 1000 airdrops, but Alice did not participate.
- At epoch 5, the total airdrop will become `2500 + 1000 = 3500` and distributed.

However. Alice can participate and exercise the epoch 4 options in epoch 5, and making the total airdrop in epoch 5 become `3500 + 1000 = 4500`.

### Proof of Concept

<https://github.com/Tapioca-DAO/tap-token//blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/option-airdrop/AirdropBroker.sol#L321-L339>

<https://github.com/Tapioca-DAO/tap-token//blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/option-airdrop/AirdropBroker.sol#L203-L220>

### Recommended Mitigation Steps

It is recommended to delete `phase4Users` in `newEpoch()`.

<https://ethereum.stackexchange.com/questions/15553/how-to-delete-a-mapping>

Or, add `phase4Users1`/`phase4Users2`/`phase4Users3`/`phase4Users4`/`phase4Users5` mappings to store the airdrops for epochs 4 through 8, respectively.

### Assessed type

Context

**[LSDan (judge) decreased severity to Low](https://github.com/code-423n4/2024-02-tapioca-findings/issues/21#issuecomment-2033054397)**

**[cccz (warden) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/21#issuecomment-2047811014):**
 > I believe this is a valid M. It's not any admin error stuff. It's a code level error, the code uses the same variables to manage airdrops at different epochs.
> 
> The only way to get rid of it is if the admin calls `newEpoch()` to enter a new epoch while resetting all the `phase4Users` variables, but `newEpoch()` is a public function and anyone can call it, which makes it hard for the admin to get rid of it.
>
> ```solidity
>     function newEpoch() external tapExists {
>         if (block.timestamp < lastEpochUpdate + EPOCH_DURATION) {
>             revert TooSoon();
>         }
> 
>         // Update epoch info
>         lastEpochUpdate = uint64(block.timestamp);
>         epoch++;
> 
>         // At epoch 4, change the epoch duration to 7 days
>         if (epoch == 4) {
>             EPOCH_DURATION = 7 days;
>         }
> 
>         // Get epoch TAP valuation
>         (bool success, uint256 _epochTAPValuation) = tapOracle.get(tapOracleData);
>         if (!success) revert Failed();
>         epochTAPValuation = uint128(_epochTAPValuation);
>         emit NewEpoch(epoch, epochTAPValuation);
>     }
> ```
>
> And as the report says, using different variables to manage airdrops for different epochs is the right way.

**[LSDan (judge) increased severity to Medium and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/21#issuecomment-2051717720):**
 > Agreed. This makes sense as a Medium.

**[0xWeiss (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/21#issuecomment-2125610255)**

*Note: For full discussion, see [here](https://github.com/code-423n4/2024-02-tapioca-findings/issues/21).*

***

## [[M-30] `AirdropBroker`: When `block.timestamp == lastEpochUpdate + EPOCH_DURATION`, users can exercise options in the new epoch.](https://github.com/code-423n4/2024-02-tapioca-findings/issues/20)
*Submitted by [cccz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/20), also found by [bin2chen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/108)*

In AirdropBroker, when a user receives an airdrop, it should only be able to exercise the options in the current epoch.

```solidity
    function _participatePhase1() internal returns (uint256 oTAPTokenID) {
        uint256 _eligibleAmount = phase1Users[msg.sender];
        if (_eligibleAmount == 0) revert NotEligible();

        // Close eligibility
        phase1Users[msg.sender] = 0;

        // Mint aoTAP
        uint128 expiry = uint128(lastEpochUpdate + EPOCH_DURATION); // Set expiry to the end of the epoch
        oTAPTokenID = aoTAP.mint(msg.sender, expiry, uint128(PHASE_1_DISCOUNT), _eligibleAmount);
    }
...
    function exerciseOption(uint256 _aoTAPTokenID, ERC20 _paymentToken, uint256 _tapAmount)
        external
        whenNotPaused
        tapExists
    {
        // Load data
        (, AirdropTapOption memory aoTapOption) = aoTAP.attributes(_aoTAPTokenID);
        if (aoTapOption.expiry < block.timestamp) revert OptionExpired();
```

For example, Alice received the airdrop for epoch 1, then Alice can participate in epoch 1 and exercise the options in epoch 1. When Alice exercises her option, the `TAP` price is determined at the beginning of epoch 1.

The problem here is that when `block.timestamp == lastEpochUpdate + EPOCH_DURATION`, `newEpoch()` can be called to enter epoch 2, and `exerciseOption()` can also be called to exercise the option of epoch 1. This allows the user to exercise the epoch 1 option at the epoch 2 `TAP` price.

```solidity
    function newEpoch() external tapExists {
        if (block.timestamp < lastEpochUpdate + EPOCH_DURATION) {
            revert TooSoon();
        }
...
    function exerciseOption(uint256 _aoTAPTokenID, ERC20 _paymentToken, uint256 _tapAmount)
        external
        whenNotPaused
        tapExists
    {
        // Load data
        (, AirdropTapOption memory aoTapOption) = aoTAP.attributes(_aoTAPTokenID);
        if (aoTapOption.expiry < block.timestamp) revert OptionExpired();
```

Consider the following scenario, Alice receives a 1000 options airdrop for epoch 1.

Epoch 1 starts, `lastEpochUpdate = day 0`, `TAP` price is 5 USD, and `TAP` price is in a downward trend. If Alice exercises the option in epoch 1, she needs to pay `5000 * 0.5 = 2500` USD.

However, when `block.timestamp == lastEpochUpdate + EPOCH_DURATION`, the current `TAP` price is 2 USD, Alice can call `newEpoch()` and `exerciseOption()` in one transaction, Alice will exercise the option at the price of epoch 2, and only needs to pay 1000 USD to get 1000 `TAP`.

### Proof of Concept

<https://github.com/Tapioca-DAO/tap-token//blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/option-airdrop/AirdropBroker.sol#L226-L233>

<https://github.com/Tapioca-DAO/tap-token//blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/option-airdrop/AirdropBroker.sol#L264-L267>

### Recommended Mitigation Steps

It is recommended that exercise is not allowed when `block.timestamp == lastEpochUpdate + EPOCH_DURATION`.

```diff
    function exerciseOption(uint256 _aoTAPTokenID, ERC20 _paymentToken, uint256 _tapAmount)
        external
        whenNotPaused
        tapExists
    {
        // Load data
        (, AirdropTapOption memory aoTapOption) = aoTAP.attributes(_aoTAPTokenID);
-       if (aoTapOption.expiry < block.timestamp) revert OptionExpired();
+       if (aoTapOption.expiry <= block.timestamp) revert OptionExpired();
```

### Assessed type

Context

**[0xRektora (Tapioca) confirmed, but disagreed with severity and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/20#issuecomment-2016904401):**
 > it's a good catch, however this is `informational`. Probability of this happening are very low. The epoch is called with an only owner function, so it can't be done within the same Tx, as for the same block, since this happens on Arbitrum with the fair sequencing and low latency, the chances are close to 0.
> On top of the incentives are extremely low for the effort being made.


**[LSDan (judge) decreased severity to Low](https://github.com/code-423n4/2024-02-tapioca-findings/issues/20#issuecomment-2033055868)**

**[cryptotechmaker (Tapioca) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/20#issuecomment-2039322466):**
 > PR [here](https://github.com/Tapioca-DAO/tap-token/pull/181).


**[cccz (warden) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/20#issuecomment-2047785922):**
 > @0xRektora - I disagree. `newEpoch()` doesn't have any modifiers like `onlyOwner`, i.e. `newEpoch()` can be called by anyone and immediately follow the `exerciseOption()` call.
 >
> ```solidity
>     function newEpoch() external tapExists {
>         if (block.timestamp < lastEpochUpdate + EPOCH_DURATION) {
>             revert TooSoon();
>         }
> 
>         // Update epoch info
>         lastEpochUpdate = uint64(block.timestamp);
>         epoch++;
> 
>         // At epoch 4, change the epoch duration to 7 days
>         if (epoch == 4) {
>             EPOCH_DURATION = 7 days;
>         }
> 
>         // Get epoch TAP valuation
>         (bool success, uint256 _epochTAPValuation) = tapOracle.get(tapOracleData);
>         if (!success) revert Failed();
>         epochTAPValuation = uint128(_epochTAPValuation);
>         emit NewEpoch(epoch, epochTAPValuation);
>     }
> ```
>
> As POC said, it's highly profitable for attackers.

**[LSDan (Judge) increased severity to Medium and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/20#issuecomment-2051720467):**
 > On review, I agree with @cccz on the impact an profitability here, due to the lack of `onlyOwner` on the `newEpoch` function.

***

## [[M-31] `sendParam.minAmountLD` slippage setting is too strict](https://github.com/code-423n4/2024-02-tapioca-findings/issues/14)
*Submitted by [ladboy233](https://github.com/code-423n4/2024-02-tapioca-findings/issues/14)*

Across the codebase, the `minAmonutLD` and `amountLD` is set to equal value:

     if (data.collateralAmount > 0) {
                address collateralWithdrawReceiver = data.withdrawCollateralParams.withdraw ? address(this) : data.user;
                uint256 collateralShare = _yieldBox.toShare(_market.collateralId(), data.collateralAmount, false);

                (Module[] memory modules, bytes[] memory calls) = IMarketHelper(data.marketHelper).removeCollateral(
                    data.user, collateralWithdrawReceiver, collateralShare
                );
                _market.execute(modules, calls, true);

                //withdraw
                if (data.withdrawCollateralParams.withdraw) {
                    uint256 collateralId = _market.collateralId();
                    if (data.withdrawCollateralParams.assetId != collateralId) revert Magnetar_WithdrawParamsMismatch();

                    // @dev re-calculate amount
                    if (collateralShare > 0) {
                        uint256 computedCollateral = _yieldBox.toAmount(collateralId, collateralShare, false);
                        if (computedCollateral == 0) revert Magnetar_WithdrawParamsMismatch();

                        data.withdrawCollateralParams.lzSendParams.sendParam.amountLD = computedCollateral;
                        data.withdrawCollateralParams.lzSendParams.sendParam.minAmountLD = computedCollateral;
                        _withdrawToChain(data.withdrawCollateralParams);
                    }
                }
            }

However, `minAmonutLD` served as a slippage control on layerzero v2 side, and 0% slippage is not always possible. The cross-chain transaction will always reverted in too strict slippage contract and block asset transfer.

<https://github.com/LayerZero-Labs/LayerZero-v2/blob/142846c3d6d51e3c2a0852c41b4c2b63fcda5a0a/oapp/contracts/oft/OFTCore.sol#L345>


     function _debitView(
            uint256 _amountLD,
            uint256 _minAmountLD,
            uint32 /*_dstEid*/
        ) internal view virtual returns (uint256 amountSentLD, uint256 amountReceivedLD) {
            // @dev Remove the dust so nothing is lost on the conversion between chains with different decimals for the token.
            amountSentLD = _removeDust(_amountLD);
            // @dev The amount to send is the same as amount received in the default implementation.
            amountReceivedLD = amountSentLD;

            // @dev Check for slippage.
            if (amountReceivedLD < _minAmountLD) {
                revert SlippageExceeded(amountReceivedLD, _minAmountLD);
            }
        }

### Recommended Mitigation Steps

Let user input a percentage and compute `minAmountLD` based on a percentage of slippage user is willing to take risk of.

### Assessed type

Token-Transfer

**[cryptotechmaker (Tapioca) confirmed, but disagreed with severity and commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/14#issuecomment-2044438123):**
 > Slippage is only for EVM to Non-EVM transfers. We're good for now. 

***

## [[M-32] Layerzero fee refund address is not handled correctly](https://github.com/code-423n4/2024-02-tapioca-findings/issues/10)
*Submitted by [ladboy233](https://github.com/code-423n4/2024-02-tapioca-findings/issues/10)*

The protocol aims to integrate with layerzero v2. To leverage layerzero infrastructure to send out cross-chain message, the user has to pay the native fee. If the user underpays the message fee, transaction reverts. If the user overpays the message fee, the excessive fee is refunded back.

However, in the current implementation, the refund address is not compose correctly.

In `MagnetarBaseModule.sol`, there is a function:

```
   function _lzCustomWithdraw(
        address _asset,
        LZSendParam memory _lzSendParam,
        uint128 _lzSendGas,
        uint128 _lzSendVal,
        uint128 _lzComposeGas,
        uint128 _lzComposeVal,
        uint16 _lzComposeMsgType
    ) private {
        PrepareLzCallReturn memory prepareLzCallReturn = _prepareLzSend(_asset, _lzSendParam, _lzSendGas, _lzSendVal);

        TapiocaOmnichainEngineHelper _toeHelper = new TapiocaOmnichainEngineHelper();
        PrepareLzCallReturn memory prepareLzCallReturn2 = _toeHelper.prepareLzCall(
            ITapiocaOmnichainEngine(_asset),
            PrepareLzCallData({
                dstEid: _lzSendParam.sendParam.dstEid,
                recipient: _lzSendParam.sendParam.to,
                amountToSendLD: 0,
                minAmountToCreditLD: 0,
                msgType: _lzComposeMsgType,
                composeMsgData: ComposeMsgData({
                    index: 0,
                    gas: _lzComposeGas,
                    value: prepareLzCallReturn.msgFee.nativeFee.toUint128(),
                    data: _lzSendParam.sendParam.composeMsg,
                    prevData: bytes(""),
                    prevOptionsData: bytes("")
                }),
                lzReceiveGas: _lzSendGas + _lzComposeGas,
                lzReceiveValue: _lzComposeVal
            })
        );

        if (msg.value < prepareLzCallReturn2.msgFee.nativeFee) {
            revert Magnetar_GasMismatch(prepareLzCallReturn2.msgFee.nativeFee, msg.value);
        }

        IOftSender(_asset).sendPacket{value: prepareLzCallReturn2.msgFee.nativeFee}(
            prepareLzCallReturn2.lzSendParam, prepareLzCallReturn2.composeMsg
        );
    }
```

First, we are [creating a temp `TapiocaOmnichainEngineHelper` contract](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarBaseModule.sol#L142), then calling `prepareLzCall` to compose the data type. The function is long, but the important thing is [that the `refundAddress` is set to `address(msg.sender)`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/tapiocaOmnichainEngine/extension/TapiocaOmnichainEngineHelper.sol#L190).

    lzSendParam_ = LZSendParam({
        sendParam: sendParam_,
        fee: msgFee_,
        extraOptions: oftMsgOptions_,
        refundAddress: address(msg.sender)
    });

    prepareLzCallReturn_ = PrepareLzCallReturn({
        composeMsg: composeMsg_,
        composeOptions: composeOptions_,
        sendParam: sendParam_,
        msgFee: msgFee_,
        lzSendParam: lzSendParam_,
        oftMsgOptions: oftMsgOptions_
    });

Who is `msg.sender`?

In this case:
- User calls contract A,
- Contract A creates contract B,
- Contract A calls contract B `prepareLzCall` method.
- Inside the `prepareLzCall` function call, `msg.sender` will be address contract A.

However, that is not what we want. The refunded fee should go to original `msg.sender` who triggered the withdraw and paid the native fee.

A simple POC can be ran:

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract Helper {
    function prepare() public returns (address) {
        return msg.sender;
    }
}

contract Magnetar {

    function compose() public returns (address) {
        Helper help = new Helper();
        return help.prepare();
    }
}

contract CounterTest is Test {

    using stdStorage for StdStorage;
    StdStorage stdlib;

    function setUp() public {

    }

    function testWhoSend() public {

        address user = vm.addr(1234);

        vm.startPrank(user);
        
        Magnetar mag = new Magnetar();

        address refundAddress = mag.compose();

        console.log("refund address is user", refundAddress == user);
        console.log("refund address is contract", refundAddress == address(mag));
    }

}
```

If we run the code with:

    forge test -vv

We are getting:

```
Running 1 test for test/Counter.t.sol:CounterTest
[PASS] testWhoSend() (gas: 196196)
Logs:
  refund address is user false
  refund address is contract true
```

Then, because the refund address is incorrectly set to contract, the original user lose refund layerzero fee. Consider that users always need to overpay the fee to send messsage. The cumulative loss of refund fee will be high and make the user lose fees.

### Recommended Mitigation Steps

Set the layerzero refund address to a user input address:

    lzSendParam_ = LZSendParam({
        sendParam: sendParam_,
        fee: msgFee_,
        extraOptions: oftMsgOptions_,
        refundAddress: refundAddress // change here
    });

    prepareLzCallReturn_ = PrepareLzCallReturn({
        composeMsg: composeMsg_,
        composeOptions: composeOptions_,
        sendParam: sendParam_,
        msgFee: msgFee_,
        lzSendParam: lzSendParam_,
        oftMsgOptions: oftMsgOptions_
    });

### Assessed type

Token-Transfer

**[0xRektora (Tapioca) confirmed](https://github.com/code-423n4/2024-02-tapioca-findings/issues/10#issuecomment-2016882001)**

**[cryptotechmaker (Tapioca) commented](https://github.com/code-423n4/2024-02-tapioca-findings/issues/10#issuecomment-2039789308):**
 > Main PR [here](https://github.com/Tapioca-DAO/tapioca-periph/pull/220).
 >
> Secondary PRs [here](https://github.com/Tapioca-DAO/tap-token/pull/182), [here](https://github.com/Tapioca-DAO/Tapioca-bar/pull/382) and [here](https://github.com/Tapioca-DAO/TapiocaZ/pull/191).

***

# Low Risk and Non-Critical Issues

For this audit, 10 reports were submitted by wardens detailing low risk and non-critical issues. The [report highlighted below](https://github.com/code-423n4/2024-02-tapioca-findings/issues/178) by **immeas** received the top score from the judge.

*The following wardens also submitted reports: [GalloDaSballo](https://github.com/code-423n4/2024-02-tapioca-findings/issues/184), [KIntern\_NA](https://github.com/code-423n4/2024-02-tapioca-findings/issues/181), [ronnyx2017](https://github.com/code-423n4/2024-02-tapioca-findings/issues/116), [carrotsmuggler](https://github.com/code-423n4/2024-02-tapioca-findings/issues/141), [bin2chen](https://github.com/code-423n4/2024-02-tapioca-findings/issues/107), [deadrxsezzz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/88), [rvierdiiev](https://github.com/code-423n4/2024-02-tapioca-findings/issues/66), [cccz](https://github.com/code-423n4/2024-02-tapioca-findings/issues/53), and [ladboy233](https://github.com/code-423n4/2024-02-tapioca-findings/issues/16).*

## [01] A lot of calls in `MagnetarAction.Permit` enables anyone to steal whitelisted tokens held by `Magnetar`

In `Magnetar` a user can batch a lot of calls to the Tapioca ecosystem. One of these is the `MagnetarAction.Permit`. This performs various permit operations, [`Magnetar::_processPermitOperation`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/Magnetar.sol#L199-L212):

```solidity
File: tapioca-periph/contracts/Magnetar/Magnetar.sol

199:        bytes4 funcSig = bytes4(_actionCalldata[:4]);
200:        if (
201:            funcSig == IPermitAll.permitAll.selector || funcSig == IPermitAll.revokeAll.selector
202:                || funcSig == IPermit.permit.selector || funcSig == IPermit.revoke.selector
203:                || funcSig == IYieldBox.setApprovalForAll.selector || funcSig == IYieldBox.setApprovalForAsset.selector 
204:                || funcSig == IERC20.approve.selector || funcSig == IPearlmit.approve.selector
205:                || funcSig == IERC721.approve.selector 
206:        ) {
207:            /// @dev Owner param check. See Warning above.
208:            _checkSender(abi.decode(_actionCalldata[4:36], (address)));
209:            // No need to send value on permit
210:            _executeCall(_target, _actionCalldata, 0, _allowFailure);
211:            return;
212:        }
```

Let's also have a look at [`MagnetarStorage::_checkSender`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/MagnetarStorage.sol#L93-L97):

```solidity
File: tapioca-periph/Magnetar/MagnetarStorage.sol

93:    function _checkSender(address _from) internal view {
94:        if (_from != msg.sender && !cluster.isWhitelisted(0, msg.sender)) {
95:            revert Magnetar_NotAuthorized(msg.sender, _from);
96:        }
97:    }
```

Here, the first argument to whatever call is done in `_processPermitOperation` is checked. The important thing here is that it always passes if the first argument is `msg.sender`.

This is troublesome for the calls: `IYieldBox::setApprovalForAll`, `IYieldBox::setApprovalForAsset`, `IERC20::approve`, and `IERC721::approve`. As they all have the operator/approvee as the first argument and use `msg.sender` as the "owner".

Hence, any of these calls would pass with `msg.sender`, granting allowance from `Magnetar` to `msg.sender` which can be any user.

### Impact

Any user can steal any whitelisted tokens held by `Magnetar`. However, as `Magnetar` is just a helper contract it is not supposed to hold any tokens.

### PoC

Test in `tap-token/test/MagnetarApproval.t.sol`:

```solidity
    function testTakeERC721() public {
        erc721.mint(address(magnetar),1);

        MagnetarCall memory approve = MagnetarCall({
            id: MagnetarAction.Permit,
            target: address(erc721),
            value: 0,
            allowFailure: false,
            call: abi.encodeWithSelector(IERC721.setApprovalForAll.selector, address(this), true)
        });

        MagnetarCall[] memory calls = new MagnetarCall[](1);
        calls[0] = approve;

        magnetar.burst(calls);

        erc721.transferFrom(address(magnetar), address(this), 1);
        assertEq(erc721.ownerOf(1),address(this));
    }

    function testTakeERC20() public {
        erc20.mint(address(magnetar),1e18);

        MagnetarCall memory approve = MagnetarCall({
            id: MagnetarAction.Permit,
            target: address(erc20),
            value: 0,
            allowFailure: false,
            call: abi.encodeWithSelector(IERC20.approve.selector, address(this), 1e18)
        });

        MagnetarCall[] memory calls = new MagnetarCall[](1);
        calls[0] = approve;

        magnetar.burst(calls);

        erc20.transferFrom(address(magnetar),address(this),1e18);
        assertEq(erc20.balanceOf(address(this)),1e18);
    }
```

Full test code can be found [here](https://gist.github.com/0ximmeas/470717ac554ea9ab350f5bf4d89fa730).

### Recommendation

Consider rethinking how `MagnetarAction.Permit` should work, as there is support in modules for a lot of the calls it is used for. Perhaps it is unnecessary to have.

## [02] Unnecessary approval in `MagnetarMintModule`

[`MagnetarMintCommonModule::_participateOnTOLP`](https://github.com/Tapioca-DAO/tapioca-periph/blob/032396f701be935b04a7e5cf3cb40a0136259dbc/contracts/Magnetar/modules/MagnetarMintCommonModule.sol#L88-L89):

```solidity
File: tapioca-periph/contracts/Magnetar/modules/MagnetarMintCommonModule.sol

88:        IERC721(lockDataTarget).approve(participateData.target, tOLPTokenId);
89:        uint256 oTAPTokenId = ITapiocaOptionBroker(participateData.target).participate(tOLPTokenId);
```

This approval is unnecessary as `TapiocaOptionBroker::participate` uses `Pearlmit` to transfer the token. Hence, the approval is needed against `Pearlmit`, not `TapiocaOptionBroker`.

### Recommendation

Consider approving `Pearlmit` instead of `participateData.target`.

## [03] Fixed min amount in `exerciseOption`

In [`TapiocaOptionBroker::exerciseOption`](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/options/TapiocaOptionBroker.sol#L396) there is a minimum amount you can claim:

```solidity
File: tap-token/blob/options/TapiocaOptionBroker.sol

396:        if (chosenAmount < 1e18) revert TooLow();
```

This amount is fixed. Hence, if `TAP` would become valuable, this can be very limiting in how much a large an option a user can exercise.

### Recommendation

Consider making this amount mutable and a call to change it.

## [04] `TwTAP` position not burnt on exit

When exiting a position in `TapiocaOptionBroker`, the users `oTAP` position [is burned](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/options/TapiocaOptionBroker.sol#L353).

This is not done when exiting a `TwTAP` position, however. This will leave a worthless NFT in the users account.

### Recommendation

Consider burning the `TwTAP` position when exiting.

## [05] Use modifier `onlyHostChain`

In `TapToken` there is a modifier `onlyHostChain` to check that the operation is done on the `governanceEid`-chain. This is used in the call `setTwTAP`.

It is, however, not used in the call [`TapToken::emitForWeek`](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/tokens/TapToken.sol#L385):

```solidity
File: tap-token/contracts/tokens/TapToken.sol

385:        if (_getChainId() != governanceEid) revert NotValid();
```

Consider using the modifier `onlyHostChain` there as well.

## [06] Unnecessary check for `0` amount in `AirdropBroker::_processOTCDeal`

In [`AirdropBroker::_processOTCDeal`](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/option-airdrop/AirdropBroker.sol#L492) there is a check for `0` amount:

```solidity
File: tap-token/contracts/option-airdrop/AirdropBroker.sol

492:        if (tapAmount == 0) revert TapAmountNotValid();
```

However, `tapAmount` can never be `0` as it is already checked to be `>1e18` before calling in [`exerciseOption`](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/option-airdrop/AirdropBroker.sol#L254):

```solidity
File: tap-token/contracts/option-airdrop/AirdropBroker.sol

254:        if (chosenAmount < 1e18) revert TooLow();
```

Consider removing the `tapAmount == 0` check in `_processOTCDeal`.

## [07] Pausing `TapiocaOptionLiquidityProvision` doesn't do anything

[`TapiocaOptionLiquidityProvision::setPause`](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/options/TapiocaOptionLiquidityProvision.sol#L363-L372):

```solidity
File: tap-token/contracts/options/TapiocaOptionLiquidityProvision.sol

363:    /**
364:     * @notice Un/Pauses this contract.
365:     */
366:    function setPause(bool _pauseState) external onlyOwner {
367:        if (_pauseState) {
368:            _pause();
369:        } else {
370:            _unpause();
371:        }
372:    }
```

However, no other call checks if the contract is paused or not. Hence, pausing will have no effect.

Consider removing the pause functionality to avoid confusion or consider what should be stopped if the contract is paused.

## [08] Unused field

[`Vesting::UserData`](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/tokens/Vesting.sol#L47-L52):

```solidity
File: tap-token/contracts/tokens/Vesting.sol

47:    struct UserData {
48:        uint256 amount;
49:        uint256 claimed;
50:        uint256 latestClaimTimestamp;
           // @audit-issue not used 
51:        bool revoked;
52:    }
```

The field `revoked` in `UserData` is not used, consider removing it.

## [09] Link broken

[`TWAML::sqrt`](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/options/twAML.sol#L144):

```solidity
File: tap-token/contracts/options/twAML.sol

144:    // babylonian method (https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Babylonian_method)
```

It's renamed to [Heron's_method](https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Heron's_method).


## [10] OpenZeppelin `draft-ERC20Permit` is deprecated

[`TapToken`](https://github.com/Tapioca-DAO/tap-token/blob/20a83b1d2d5577653610a6c3879dff9df4968345/contracts/tokens/TapToken.sol#L11) uses OpenZeppelin `draft-ERC20Permit.sol`, this is the contents:

```solidity
// EIP-2612 is Final as of 2022-11-01. This file is deprecated.

import "./ERC20Permit.sol";
```

Consider importing `ERC20Permit.sol` directly instead.

***

# Gas Optimizations

For this audit, 1 reports were submitted by wardens detailing gas optimizations. The [report highlighted below](https://github.com/code-423n4/2024-02-tapioca-findings/issues/183) by **GalloDaSballo** received the top score from the judge.

The following are very simply and effective refactorings to save gas.

## TapToken

### Make the variable immutable - 2.1k gas

https://github.com/Tapioca-DAO/tap-token/blob/050e666142e61018dbfcba64d295f9c458c69700/contracts/tokens/TapToken.sol#L65-L66

```solidity
    uint256 public governanceEid; /// IMMUTABLE
```

### Use Constant instead of recomputing hashes - 200+ gas

https://github.com/Tapioca-DAO/tap-token/blob/050e666142e61018dbfcba64d295f9c458c69700/contracts/tokens/TapToken.sol#L327

```solidity
keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
```

https://github.com/OpenZeppelin/openzeppelin-contracts/blob/7417c5946f8a213a8e61eca8d3c5247bf3854249/contracts/token/ERC20/extensions/ERC20Permit.sol#L21C1-L22C105


### Make the variable immutable - 2.1k gas

https://github.com/Tapioca-DAO/tap-token/blob/050e666142e61018dbfcba64d295f9c458c69700/contracts/governance/twTAP.sol#L111-L112

```solidity
    uint256 public creation; // Week 0 starts here /// @audit Make Immutable
```

### Cache to mem - 100 gas

https://github.com/Tapioca-DAO/tap-token/blob/050e666142e61018dbfcba64d295f9c458c69700/contracts/governance/twTAP.sol#L468-L469

```solidity
        WeekTotals storage totals = weekTotals[lastProcessedWeek];
```

## TOLP

### Do not copy `sgl` to `memory`, instead use a pointer - 2.1k gas

https://github.com/Tapioca-DAO/tap-token/blob/050e666142e61018dbfcba64d295f9c458c69700/contracts/options/TapiocaOptionLiquidityProvision.sol#L197-L201

```solidity
        SingularityPool memory sgl = activeSingularities[_singularity]; /// GAS DO NOT COPY
        if (sgl.rescue) revert SingularityInRescueMode();

        uint256 sglAssetID = sgl.sglAssetID;
        if (sglAssetID == 0) revert SingularityNotActive();
```

-> Change to storage to cache the pointer, not copy the data.

`SingularityPool storage sgl = activeSingularities[_singularity]; /// GAS DO NOT COPY`

## Use the memory value instead of storage - 100 gas

https://github.com/Tapioca-DAO/tap-token/blob/050e666142e61018dbfcba64d295f9c458c69700/contracts/options/TapiocaOptionBroker.sol#L421-L424

```solidity
        bool success;
        (success, epochTAPValuation) = tapOracle.get(tapOracleData);
        if (!success) revert Failed();
        emit NewEpoch(epoch, epochTAP, epochTAPValuation); /// @audit GAS
```

***

# Disclosures

C4 is an open organization governed by participants in the community.

C4 audits incentivize the discovery of exploits, vulnerabilities, and bugs in smart contracts. Security researchers are rewarded at an increasing rate for finding higher-risk issues. Audit submissions are judged by a knowledgeable security researcher and solidity developer and disclosed to sponsoring developers. C4 does not conduct formal verification regarding the provided code but instead provides final verification.

C4 does not provide any guarantee or warranty regarding the security of this project. All smart contract software should be used at the sole risk and responsibility of users.
