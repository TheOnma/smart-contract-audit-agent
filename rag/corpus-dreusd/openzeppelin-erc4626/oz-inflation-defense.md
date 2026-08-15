# OpenZeppelin — Novel Defense Against ERC4626 Inflation Attacks

(Extracted from web; technical content for RAG.)

Research
 /
Security Insights
/
A Novel Defense Against ERC4626 Inflation Attacks
Security Insights
A Novel Defense Against ERC4626 Inflation Attacks
Table of Content
-
August 15, 2023
OpenZeppelin
OpenZeppelin
ERC4626, an extension of the familiar ERC20, provides a standardized interface for token vaults, empowering developers to construct secure and composable solutions. It's crucial to be aware of potential security vulnerabilities, such as inflation attacks, that can affect ERC4626 token vaults.
Understanding the Inflation Attack
ERC4626 token vaults operate by issuing shares in exchange for deposited assets. The exchange rate between shares and assets determines the value of each share. In an inflation attack, an attacker manipulates the exchange rate to benefit themselves at the expense of other users. By exploiting the rounding down of shares during deposit, the attacker can dilute the value of other users' deposits.
New vaults are at the greatest risk of inflation attacks. Let’s illustrate this with an example: Suppose a user is about to deposit 100 tokens into a new vault as the first depositor. If an attacker front-runs this initial deposit with even 1 wei, this minuscule deposit would still garner the attacker a 100% share of the pool.
Next, the attacker donates an amount greater than or equal to 100 tokens to the vault. This action increases the total balance of the pool, while maintaining the number of shares in circulation.
By the time the initial user’s deposit of 100 tokens makes it to the pool, the calculation for their share ends up being zero due to the way pool shares are calculated with the donated token balance (in this example, 100/101 rounds down to 0).
Finally, the attacker withdraws their share from the pool. Since they are the only one with any shares, this withdrawal equals the balance of the vault. This means the attacker also withdraws the 100 tokens deposited by the initial user, effectively stealing their deposit.
OpenZeppelin’s goal was to offer an implementation of ERC4626 that would be out-of-the-box secure against such threats.
Defending Against Inflation Attacks
Several mitigation strategies were considered, each carrying its own potential benefits and drawbacks.
1. Using an ERC4626 Router
This is a relatively straightforward approach, but it may only circumvent the issue rather than address it directly.
Pros:
It is
already available for use
, which makes it easy to implement.
The logic behind this strategy is straightforward, making it easier for developers to understand and utilize.
There is no need to alter the vault's code, which simplifies the process.
Cons:
It utilizes more gas as the router needs to take custody before performing vault operations.
It introduces an additional trust assumption, as the router becomes a critical element with permission to spend user tokens.
2. Keeping Track of Total Assets Internally
The second strategy aims to negate the effect of direct transfers by keeping track of the assets held by the vault internally. This means that donated tokens are not accounted for, which effectively eliminates the risk of inflation attacks.
Pros:
It removes the inflation risk completely.
The logic is easy to understand.
The strategy is self-contained to the vault, eliminating the dependency on third-party contracts.
It maintains the same workflow for Externally Owned Accounts (EOAs) and smart contracts.
It can be provided as an optional module, allowing developers to add it on top of the base implementation.
Cons:
This strategy is not generic; it doesn't work with re-basing tokens.
There is a risk of token lock (burn) or the need for a trusted admin.
Some gas cost overhead remains, although it is less than the previous option.
3. Creating "Dead Shares"
This strategy is inspired by Uniswap V2, which created dead LP shares when the first liquidity was deposited. In ERC4626 vaults, a similar approach could be implemented by minting dead shares upon the first deposit/mint.
Pros:
There is very limited gas overhead.
Like the second strategy, it can be provided as an optional module that developers can add to the base implementation.
Cons:
The strategy doesn't completely resolve the issue. Inflation attacks are still possible, at a reduced profit.
The amount of dead shares required must be answered case-by-case.
It discourages legitimate early liquidity providers.
It locks a fraction of the assets in the vault that can never be withdrawn.
Example Mitigation Strategies in Deployment
To construct a solution that effectively mitigates the risk of inflation attacks on ERC-4626, we examined existing strategies throughout the ecosystem.
Morpho DAO: Initial Asset Deposits
Morpho DAO mitigates inflation attacks by depositing assets into the vault upon initialization. The corresponding shares are minted to the vault itself, which functions as a non-operational address. This strategy is akin to the creation of dead shares, but the loss is borne by the project. The more assets deposited initially, the more challenging it becomes to execute an inflation attack. However, sufficient funds must be available for the initial deposit, as they are effectively lost.
While the implementation process for this approach is straightforward, the address of the vault needs to be precomputed, and approval must be granted in advance of deployment.
YieldBox: Virtual Shares and Assets
YieldBox calculates the exchange rate by adding a "virtual" quantity of shares and assets to the vault. This approach mirrors the behavior of the creation of dead shares but without the necessity to burn any tokens to mint them. While it rectifies the drawbacks for early depositors, a portion of any tokens that the vault receives from direct transfers or re-basing will be lost.
An internal fixed-point representation for shares is established by setting the asset offset to 1 and the supply offset to 1e8. This allows for the representation of shares as small as 0.00000001 wei, and the loss to real users, if any, will be negligible, as the quantity of virtual assets is minimal.
The Defense: Virtual Shares and Decimals Offset
For the implementation in OpenZeppelin contracts, we designed a solution that made use of both a virtual offset and a decimal offset. This prevents the downside of dead share creation, namely having to give up some of the underlying asset.
A decimals offset
 allows to directly tune the profitability of the attack by increasing the amount of decimal places to represent the shares beyond that of the underlying token.
A virtual offset
 restricts the attacker's ability to manipulate the exchange rate effectively by including both virtual shares and virtual assets in the exchange rate computation. The virtual assets enforce the conversion rate when the vault is empty.
A balance offset due to virtual assets coupled with the increased precision of decimal offset reduces the rounding error when computing the amount of shares. Attacks lose their profitability because virtual assets and shares capture part of the donation.
Even without a decimal offset, the presence of virtual shares and assets renders this attack unprofitable. The greater the offset, the more an attacker would lose during the attack, therefore the greater the security from inflation attacks.
Staying Safe
We implemented ERC-4626 to prioritize security and allow developers to focus on building. By leveraging the functionality of OpenZeppelin Contracts and implementing the recommended defense mechanisms, developers can fortify their applications and protect user assets.
If you’d like to work with OpenZeppelin on a security audit or require further guidance on securing your ERC4626 vaults, please get in touch.
References:
-
ERC4626 Documentation
-
ERC4626Fees
