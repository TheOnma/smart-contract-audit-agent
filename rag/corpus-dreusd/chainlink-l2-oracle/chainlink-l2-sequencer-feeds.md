# Chainlink — L2 Sequencer Uptime Feeds

(Extracted from web; technical content for RAG.)

L2 Sequencer Uptime Feeds
Optimistic rollups (e.g., Arbitrum, Optimism) and many ZK-rollups rely on sequencers to efficiently manage transaction ordering, execution, and batching before submitting them to Layer 1 (L1) blockchains like Ethereum. The sequencer plays a crucial role in optimizing transaction throughput, reducing fees, and ensuring fast transaction confirmations on L2 networks, making it a key component of their scalability and performance.
However, if the sequencer becomes unavailable, users will lose access to the standard read/write APIs, preventing them from interacting with applications on the L2 network. Although the L2 chain's security and state commitments remain enforced by Layer 1, no new batched blocks will be produced by the sequencer. Users with sufficient technical expertise can still interact directly with the network through the underlying rollup contracts on L1. However, this process is more complex and costly, creating an unfair advantage for those who can bypass the sequencer. This imbalance in access can lead to disruptions or distortions in applications, such as liquidations or market operations that rely on timely transactions.
To mitigate these risks, your applications can integrate a
Sequencer Uptime Data Feed
, which continuously monitors and records the last known status of the sequencer. By utilizing this feed, you can:
Detect sequencer downtime in real time.
Implement a grace period to prevent mass liquidations or unexpected disruptions.
Ensure fair access to services by temporarily pausing operations during sequencer failures.
This proactive approach enhances the resilience and fairness of applications operating on L2 networks, ensuring a more stable and equitable user experience.
Supported Networks
You can find proxy addresses for the L2 sequencer feeds at the following addresses:
Arbitrum
Arbitrum Mainnet:
0xFdB631F5EE196F0ed6FAa767959853A9F217697D
BASE
BASE Mainnet:
0xBCF85224fc0756B9Fa45aA7892530B47e10b6433
Celo
Celo Mainnet:
0x4CD491Dc27C8B0BbD10D516A502856B786939d18
Mantle
Mantle Mainnet:
0xaDE1b9AbB98c6A542E4B49db2588a3Ec4bF7Cdf0
MegaETH
MegaETH Mainnet:
0x78B2195A21B8BBe82acaB43F90F9180E9513FD0C
Metis
Andromeda Mainnet:
0x58218ea7422255EBE94e56b504035a784b7AA204
OP
OP Mainnet:
0x371EAD81c9102C9BF4874A9075FFFf170F2Ee389
Scroll
Scroll Mainnet:
0x45c2b8C204568A03Dc7A2E32B71D67Fe97F908A9
Soneium
Soneium Mainnet:
0xaDE1b9AbB98c6A542E4B49db2588a3Ec4bF7Cdf0
X Layer
X Layer Mainnet:
0x45c2b8C204568A03Dc7A2E32B71D67Fe97F908A9
ZKsync
zkSync Mainnet:
0x0E6AC8B967393dcD3D36677c126976157F993940
Real-time Monitoring Process
Arbitrum
The diagram below shows how these feeds update and how a consumer retrieves the status of the Arbitrum sequencer.
Chainlink nodes trigger an OCR round every 30s and update the sequencer status by calling the
validate
 function in the
ArbitrumValidator
 contract
 by calling it through the
ValidatorProxy
 contract
.
The
ArbitrumValidator
 checks to see if the latest update is different from the previous update. If it detects a difference, it places a message in the
Arbitrum inbox contract
.
The inbox contract sends the message to the
ArbitrumSequencerUptimeFeed
 contract
. The message calls the
updateStatus
 function in the
ArbitrumSequencerUptimeFeed
 contract and updates the latest sequencer status to 0 if the sequencer is up and 1 if it is down. It also records the block timestamp to indicate when the message was sent from the L1 network.
A consumer contract on the L2 network can read these values from the
ArbitrumUptimeFeedProxy
 contract
, which reads values from the
ArbitrumSequencerUptimeFeed
 contract.
Handling Arbitrum Outages
If the Arbitrum network becomes unavailable, the
ArbitrumValidator
 contract continues to send messages to the L2 network through the delayed inbox on L1. This message stays there until the sequencer is back up again. When the sequencer comes back online after downtime, it processes all transactions from the delayed inbox before it accepts new transactions. The message that signals when the sequencer is down will be processed before any new messages with transactions that require the sequencer to be operational.
Other Supported Networks
On BASE, Celo, Mantle, Metis, OP, Scroll, Soneium and zkSync, the sequencer's status is relayed from L1 to L2 where the consumer can retrieve it.
On the L1 network:
A network of node operators runs the external adapter to post the latest sequencer status to the
AggregatorProxy
 contract and relays the status to the
Aggregator
 contract. The
Aggregator
 contract calls the
validate
 function in the
OptimismValidator
 contract.
The
OptimismValidator
 contract calls the
sendMessage
 function in the
L1CrossDomainMessenger
 contract. This message contains instructions to call the
updateStatus(bool status, uint64 timestamp)
 function in the sequencer uptime feed deployed on the L2 network.
The
L1CrossDomainMessenger
 contract calls the
enqueue
 function to enqueue a new message to the
CanonicalTransactionChain
.
The
Sequencer
 processes the transaction enqueued in the
CanonicalTransactionChain
 contract to send it to the L2 contract.
On the L2 network:
The
Sequencer
 posts the message to the
L2CrossDomainMessenger
 contract.
The
L2CrossDomainMessenger
 contract relays the message to the
OptimismSequencerUptimeFeed
 contract.
The message relayed by the
L2CrossDomainMessenger
 contains instructions to call
updateStatus
 in the
OptimismSequencerUptimeFeed
 contract.
Consumers can then read from the
AggregatorProxy
 contract, which fetches the latest round data from the
OptimismSequencerUptimeFeed
 contract.
Handling Other Supported Network Outages
If the sequencer is down, messages cannot be transmitted from L1 to L2 and
no L2 transactions are executed
. Instead, messages are enqueued in the
CanonicalTransactionChain
 on L1 and only processed in the order they arrived later when the sequencer comes back up. As long as the message from the validator on L1 is already enqueued in the
CTC
, the flag on the sequencer uptime feed on L2 will be guaranteed to be flipped prior to any subsequent transactions. The transaction that flips the flag on the uptime feed will be executed before transactions that were enqueued after it. This is further explained in the diagrams below.
When the Sequencer is down, all L2 transactions sent from the L1 network wait in the pending queue.
Transaction 3
 contains Chainlink's transaction to set the status of the sequencer as being down on L2.
Transaction 4
 is a transaction made by a consumer that is dependent on the sequencer status.
After the sequencer comes back up, it moves all transactions in the pending queue to the processed queue.
Transactions are processed in the order they arrived so
Transaction 3
 is processed before
Transaction 4
.
Because
Transaction 3
 happens before
Transaction 4
,
Transaction 4
 will read the status of the Sequencer as being down and responds accordingly.
Example Consumer Contract
This example code works on any network that supports Solidity. Create the consumer contract for sequencer uptime feeds similarly to the contracts that you use for other
Chainlink Data Feeds
. Configure the constructor using the following variables:
Configure the
sequencerUptimeFeed
 object with the
sequencer uptime feed proxy address
 for your L2 network.
Configure the
dataFeed
 object with one of the
Data Feed proxy addresses
 that are available for your network.
// SPDX-License-Identifier: MIT
pragma
solidity
^
0.8.7
;
import
{
AggregatorV2V3Interface
}
from
"@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV2V3Interface.sol"
;
/**
 * THIS IS AN EXAMPLE CONTRACT THAT USES HARDCODED VALUES FOR CLARITY.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract
DataConsumerWithSequencerCheck
{
  AggregatorV2V3Interface
internal
 dataFeed
;
  AggregatorV2V3Interface
internal
 sequencerUptimeFeed
;
uint256
private
constant
 GRACE_PERIOD_TIME
=
3600
;
  error
SequencerDown
(
)
;
  error
GracePeriodNotOver
(
)
;
/**
   * Network: OP Mainnet
   * Data Feed: BTC/USD
   * Data Feed address: 0xD702DD976Fb76Fffc2D3963D037dfDae5b04E593
   * Uptime Feed address: 0x371EAD81c9102C9BF4874A9075FFFf170F2Ee389
   * For a list of available Sequencer Uptime Feed proxy addresses, see:
   * https://docs.chain.link/docs/data-feeds/l2-sequencer-feeds
   */
constructor
(
)
{
    dataFeed
=
AggregatorV2V3Interface
(
0xD702DD976Fb76Fffc2D3963D037dfDae5b04E593
)
;
    sequencerUptimeFeed
=
AggregatorV2V3Interface
(
0x371EAD81c9102C9BF4874A9075FFFf170F2Ee389
)
;
}
// Check the sequencer status and return the latest data
function
getChainlinkDataFeedLatestAnswer
(
)
public
view
returns
(
int256
)
{
// prettier-ignore
(
/*uint80 roundID*/
,
int256
 answer
,
uint256
 startedAt
,
/*uint256 updatedAt*/
,
/*uint80 answeredInRound*/
)
=
 sequencerUptimeFeed
.
latestRoundData
(
)
;
// Answer == 0: Sequencer is up
// Answer == 1: Sequencer is down
bool
 isSequencerUp
=
 answer
==
0
;
if
(
!
isSequencerUp
)
{
revert
SequencerDown
(
)
;
}
// Make sure the grace period has passed after the
// sequencer is back up.
uint256
 timeSinceUp
=
 block
.
timestamp
-
 startedAt
;
if
(
timeSinceUp
<=
 GRACE_PERIOD_TIME
)
{
revert
GracePeriodNotOver
(
)
;
}
// prettier-ignore
(
/*uint80 roundID*/
,
int256
 data
,
/*uint startedAt*/
,
/*uint timeStamp*/
,
/*uint80 answeredInRound*/
)
=
 dataFeed
.
latestRoundData
(
)
;
return
 data
;
}
}
Open in Remix
What is Remix?
The
sequencerUptimeFeed
 object returns the following values:
answer
: A variable with a value of either
0
 or
1
0: The sequencer is up
1: The sequencer is down
startedAt
: This timestamp indicates when the sequencer feed changed status. When the sequencer comes back up after an outage, wait for the
GRACE_PERIOD_TIME
 to pass before accepting answers from the data feed. Subtract
startedAt
 from
block.timestamp
 and revert the request if the result is less than the
GRACE_PERIOD_TIME
.
The
startedAt
 variable returns
0
 only on Arbitrum when the Sequencer Uptime contract is not yet initialized. For L2 chains other than Arbitrum,
startedAt
 is set to
block.timestamp
 on construction and
startedAt
 is never
0
. After the feed begins rounds, the
startedAt
 timestamp will always indicate when the sequencer feed last changed status.
If the sequencer is up and the
GRACE_PERIOD_TIME
 has passed, the function retrieves the latest answer from the data feed using the
dataFeed
 object.
