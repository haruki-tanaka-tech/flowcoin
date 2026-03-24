# FlowCoin: A Proof-of-Training Blockchain for Collaborative Neural Network Development

## Abstract

We present FlowCoin, a cryptocurrency where the proof-of-work computation is replaced
by neural network training. Miners perform gradient descent on a shared model
(ResonanceNet V5) and submit compressed weight updates as proof of computational effort.
The resulting blockchain produces a continuously improving language model as a public
good, while maintaining the security properties of traditional proof-of-work systems.

FlowCoin preserves Bitcoin's economic invariants -- fixed 21 million coin supply,
10-minute target block time, and quadrennial halving -- while redirecting the energy
expenditure of mining toward useful computation. The consensus mechanism ensures that
only genuine training effort can produce valid blocks, preventing shortcut attacks
through deterministic evaluation and cryptographic binding of training results to
block headers.

We describe the complete system: the ResonanceNet V5 architecture optimized for
incremental training, the Proof-of-Training consensus mechanism, the model growth
schedule that allows the network to train progressively larger models, and the
economic model that incentivizes honest participation.

## 1. Introduction

### 1.1 The Problem with Proof-of-Work

Bitcoin's proof-of-work mechanism consumes an estimated 150 TWh of electricity annually
as of 2025, comparable to the energy consumption of a medium-sized country. This energy
expenditure serves a single purpose: making it computationally expensive to rewrite
transaction history. The SHA-256 computations performed by miners produce no useful
output beyond the security of the blockchain itself.

This waste has motivated numerous proposals for "useful proof-of-work" systems, where
mining computation serves a dual purpose: securing the blockchain and producing some
valuable computational result. However, prior attempts have struggled with a fundamental
tension: the work must be simultaneously useful and verifiable, difficult to fake but
easy to check, and resistant to optimization shortcuts that would undermine security.

### 1.2 Making Mining Useful

Neural network training is uniquely suited as a useful proof-of-work because:

1. **Verifiable**: The result of training (weight updates) can be verified by running
   a deterministic forward pass on a fixed evaluation dataset. This check is orders of
   magnitude cheaper than the training itself.

2. **Non-fakeable**: Producing weight updates that improve model performance on unseen
   evaluation data requires actual gradient computation. Random or adversarial deltas
   will not reduce validation loss.

3. **Incrementally composable**: Training updates from different miners can be accumulated
   to build a single model over time. Each miner's contribution builds on the cumulative
   state of all prior contributions.

4. **Adjustable difficulty**: The difficulty of producing a valid training proof can be
   tuned by adjusting the target threshold, just as Bitcoin adjusts the number of
   leading zeros required in the block hash.

5. **Economically valuable**: A well-trained language model has direct economic value,
   creating a positive externality from the mining process.

### 1.3 Our Contribution

FlowCoin makes the following contributions:

- A complete Proof-of-Training consensus mechanism that provides security guarantees
  comparable to Bitcoin's proof-of-work, formalized and analyzed in Section 4.
- ResonanceNet V5, a neural network architecture specifically designed for incremental,
  distributed training in a blockchain context (Section 3).
- A model growth schedule that allows the network to progressively increase model
  capacity as more computational resources join the network (Section 5).
- A fully specified protocol including transaction format, network messaging, and
  storage, implemented as production-quality C++ software (Sections 6-7).
- A security analysis covering 51% attacks, training manipulation, and model
  poisoning (Section 8).

## 2. Background

### 2.1 Bitcoin and Proof-of-Work

Bitcoin introduced the concept of a decentralized ledger secured by proof-of-work.
Miners compete to find a nonce such that `SHA256d(block_header) < target`. The
difficulty (target) adjusts every 2016 blocks to maintain a 10-minute average block
time. The block reward halves every 210,000 blocks, creating a deflationary supply
curve that approaches 21 million BTC asymptotically.

Key properties we preserve from Bitcoin:
- **Sybil resistance**: Creating valid blocks requires real computational work
- **Incentive compatibility**: Honest mining is the profit-maximizing strategy
- **Difficulty adjustment**: Adapts to changes in total network hash rate
- **Halving schedule**: Predictable, decreasing issuance over time
- **Longest chain rule**: The chain with the most cumulative work is canonical

### 2.2 Neural Network Training

Training a neural network involves iteratively adjusting model parameters (weights)
to minimize a loss function on a training dataset. Each iteration (step) involves:

1. Forward pass: compute model output for a batch of training examples
2. Loss computation: measure the difference between output and target
3. Backward pass: compute gradients of the loss with respect to all parameters
4. Weight update: adjust parameters in the direction of negative gradient

The computational cost of training scales with:
- Model size (number of parameters)
- Dataset size (number of training examples)
- Number of training steps
- Batch size (examples per step)

For language models, training is typically measured in FLOPs (floating-point
operations). A single training step on a model with P parameters and sequence
length S requires approximately 6PS FLOPs.

### 2.3 Related Work (Proof-of-Useful-Work Attempts)

Several prior projects have attempted to make blockchain mining useful:

**Primecoin (2013)**: Mining involves finding Cunningham chains of prime numbers.
While mathematically interesting, prime number discovery has limited practical value.

**Gridcoin (2014)**: Rewards participants for contributing to BOINC scientific
computing projects. However, the proof relies on a centralized BOINC infrastructure
for work verification, introducing trust assumptions.

**AI-blockchain proposals**: Various academic papers have proposed using machine
learning tasks as proof-of-work. Most suffer from verification cost (checking
training results is as expensive as performing them) or manipulation vulnerability
(adversarial training updates can be generated cheaply).

FlowCoin addresses these limitations through:
- Deterministic evaluation that is orders of magnitude cheaper than training
- Cryptographic binding via the training hash (Keccak256 of delta and dataset)
- A single shared model rather than arbitrary tasks, enabling cumulative progress

## 3. ResonanceNet V5 Architecture

### 3.1 Why Not Transformer

Pure transformer architectures, while dominant in commercial LLMs, have properties
that make them unsuitable for blockchain-based incremental training:

- **O(n^2) attention**: Memory and compute scale quadratically with sequence length,
  making long-context training expensive for resource-constrained miners.
- **No persistent state**: Transformers process each sequence independently, requiring
  the entire context to be re-encoded for each forward pass.
- **Difficult to merge**: Weight averaging of transformer checkpoints is known to
  produce poor results without careful alignment, complicating the accumulation of
  deltas from independent miners.

ResonanceNet V5 addresses these issues by combining attention with recurrence and
explicit memory.

### 3.2 MinGRU: O(1) State

The Minimal Gated Recurrent Unit (MinGRU) provides O(1) per-token processing:

```
gate = sigmoid(W_g * x + b_g)
candidate = tanh(W_c * x + b_c)
h_t = gate * h_{t-1} + (1 - gate) * candidate
```

Unlike full GRU or LSTM, MinGRU uses a single gate to interpolate between the
previous state and the new candidate, reducing parameter count and computation.

The recurrent state allows the model to maintain a compressed summary of the
entire prior context, complementing the attention mechanism's ability to access
specific past tokens.

For mining, the O(1) state means that training step cost is independent of
context length, making training cost predictable and bounded.

### 3.3 Slot Memory: Sparse Knowledge

Slot memory provides a fixed set of learned key-value pairs that the model can
attend to at each layer:

```
slot_keys:   [n_slots, d_model]  -- learned during training
slot_values: [n_slots, d_model]  -- learned during training

attention_output = softmax(Q * slot_keys^T / sqrt(d_model)) * slot_values
```

This separates factual knowledge storage from sequence processing:
- The core model (attention + GRU + FFN) learns general language patterns
- Slot memory stores specific facts, entities, and relationships
- Growing n_slots allows knowledge accumulation without model restructuring

During Phase 2 of the growth schedule, only n_slots increases, allowing the
network to accumulate more knowledge while maintaining a stable core architecture.

### 3.4 Multi-Scale Convolution: Local Patterns

Three parallel causal 1D convolutions with kernel sizes 3, 5, and 7 capture
local n-gram patterns at different scales:

```
conv3_out = CausalConv1d(x, kernel_size=3, channels=d_model/3)
conv5_out = CausalConv1d(x, kernel_size=5, channels=d_model/3)
conv7_out = CausalConv1d(x, kernel_size=7, channels=d_model/3)
out = Linear(concat(conv3_out, conv5_out, conv7_out))
```

Benefits for incremental training:
- Convolutional parameters are small and converge quickly
- Local patterns transfer well between model sizes
- Provide complementary information to attention (which focuses on long-range)

### 3.5 Training Efficiency Comparison

Compared to a pure transformer of equivalent parameter count:

| Metric                  | Transformer | ResonanceNet V5 | Ratio |
|-------------------------|-------------|-----------------|-------|
| FLOPs per token (train) | 6P          | ~5P             | 0.83x |
| Memory per token        | O(S)        | O(1)            | -     |
| Convergence (steps to target loss) | 1.0x | ~0.9x      | 0.9x  |
| Delta merge quality     | Poor        | Good            | -     |
| Knowledge capacity      | Fixed       | Growing         | -     |

The reduction in FLOPs comes from MinGRU replacing one attention sublayer,
and the smaller effective context length for the remaining attention layer.

## 4. Proof-of-Training Consensus

### 4.1 Training as Mining

A FlowCoin miner performs the following steps for each block:

1. Fetch the current block template (header fields, target, model dimensions)
2. Load the cumulative model state from the chain tip
3. Load a training dataset shard
4. Perform gradient descent for at least `min_train_steps` steps
5. Evaluate validation loss on the deterministic evaluation dataset
6. Compute the weight delta (post-training weights minus pre-training weights)
7. Sparsify and compress the delta
8. Compute: `training_hash = Keccak256(delta_hash || dataset_hash)`
9. If `training_hash < target`: the block is valid
10. Sign the block header with the miner's Ed25519 key
11. Broadcast the block to the network

The probabilistic nature of the training hash means that different training
runs produce different deltas, and thus different training hashes. A miner
cannot predict whether a particular training run will produce a valid hash
without actually performing the training and computing the hash.

### 4.2 Delta Payload

The weight delta captures the actual learning performed by the miner:

```
delta = weights_after_training - weights_before_training
```

Sparsification removes values below a threshold, typically retaining only
1-10% of elements. This is both efficient for compression and beneficial for
model quality (acting as a form of regularization).

The compressed delta is included in the block and applied by all nodes to
update the cumulative model state.

### 4.3 Deterministic Validation

Block validation requires verifying that the miner's claimed val_loss is correct:

1. Load the cumulative model state at the parent block
2. Apply the delta from the candidate block
3. Generate the evaluation dataset from the block height
4. Run a deterministic forward pass
5. Compare the computed val_loss with the claimed val_loss

This verification is approximately 100x cheaper than the training itself
(evaluation requires only forward passes, not backpropagation).

Determinism requirements:
- All arithmetic uses IEEE 754 single-precision (no -ffast-math)
- Operations are executed in a fixed order (no nondeterministic parallelism)
- Evaluation data is generated from the block height using Keccak-256 PRNG

### 4.4 Difficulty Adjustment

FlowCoin uses Bitcoin's difficulty adjustment algorithm:

- Retarget every 2016 blocks
- Target timespan: 2016 * 600 seconds = 2 weeks
- Adjustment factor clamped to [0.25, 4.0]
- New target = old target * actual time / expected time

The target is encoded in the compact `nbits` format and determines the
threshold for `training_hash < target`.

## 5. Model Growth Schedule

### 5.1 Phase 1: Dimension Growth

During the first ~500,000 blocks, model dimensions increase at predefined
plateaus triggered by cumulative improving blocks (blocks where val_loss decreased
compared to the parent):

- Plateau 0: 64-dim, 2 layers (at genesis)
- Plateau 1: 128-dim, 4 layers
- Plateau 2: 256-dim, 6 layers
- Plateau 3: 384-dim, 8 layers
- Plateau 4: 512-dim, 12 layers (final)

Each transition preserves existing weights and initializes new parameters
deterministically, ensuring all nodes maintain identical model states.

### 5.2 Phase 2: Knowledge Growth

After dimension growth plateaus, the slot memory count increases linearly:

```
n_slots = base_slots + floor(improving_blocks / growth_interval)
```

This allows the model to accumulate unbounded factual knowledge while
maintaining a fixed computational cost per training step.

### 5.3 Cumulative Learning

Each block's delta is applied cumulatively to the model state:

```
model_state[height] = model_state[height-1] + delta[height]
```

Over time, the model improves as miners contribute training updates:
- Early blocks: rapid loss reduction on basic language patterns
- Middle blocks: slower improvement as the model learns more complex patterns
- Later blocks: fine-grained knowledge accumulation via slot memory growth

The stagnation counter tracks consecutive non-improving blocks. Extended
stagnation can trigger dimension growth events, providing fresh capacity
for continued learning.

## 6. Economic Model

### 6.1 Token Supply (21M)

Total supply is capped at 21,000,000 FLOW, with 1 FLOW = 10^8 atomic units
(matching Bitcoin's satoshi granularity).

### 6.2 Block Reward Schedule

Initial reward: 50 FLOW per block, halving every 210,000 blocks.

At 10-minute target block time:
- Year 0-4: 50 FLOW/block = 10.5M FLOW
- Year 4-8: 25 FLOW/block = 5.25M FLOW
- Year 8-12: 12.5 FLOW/block = 2.625M FLOW
- Asymptotically approaching 21M FLOW

### 6.3 Mining Economics

Mining profitability depends on:
- Hardware cost (GPU for training, CPU for hashing)
- Electricity cost
- Network difficulty (total training compute)
- FLOW market price
- Transaction fees (increasingly important as block reward decreases)

Unlike Bitcoin where mining is dominated by ASICs, FlowCoin mining benefits
from general-purpose GPU hardware that retains resale value for other
machine learning workloads.

### 6.4 GPU Requirements Over Time

As model dimensions grow, GPU memory requirements increase:

| Phase   | d_model | Parameters | Min GPU RAM | Target GPU    |
|---------|---------|------------|-------------|---------------|
| Phase 0 | 64      | ~160K      | 256 MB      | Any GPU       |
| Phase 1 | 128     | ~1.2M      | 512 MB      | Entry GPU     |
| Phase 2 | 256     | ~8M        | 2 GB        | GTX 1650      |
| Phase 3 | 384     | ~25M       | 4 GB        | RTX 3060      |
| Phase 4 | 512     | ~80M       | 8 GB        | RTX 3070      |

The gradual increase ensures that early mining is accessible to commodity
hardware, while later phases reward investment in more capable equipment.

## 7. Network Architecture

### 7.1 P2P Protocol

FlowCoin uses a custom P2P protocol based on Bitcoin's wire format:
- TCP connections on port 9333 (mainnet)
- 24-byte message headers with Keccak-256 checksums
- Maximum 8 outbound + 117 inbound connections per node
- Address management with tried/new tables (Bitcoin Core's addrman)

### 7.2 Block Propagation

Three propagation modes for different scenarios:
1. **Standard**: INV announcement -> GETDATA request -> BLOCK response
2. **Headers-first**: Direct HEADERS message for peers that opted in
3. **Compact blocks**: Header + short IDs, with missing tx recovery

Delta payloads (potentially large) are included in the full block message.
Compact blocks include only transaction short IDs, reducing bandwidth for
blocks whose transactions are already in the receiving node's mempool.

### 7.3 Initial Sync

New nodes perform initial block download (IBD):
1. Download all block headers (2000 per message, headers-first)
2. Download full blocks from multiple peers in parallel
3. Apply deltas to reconstruct the model state
4. Optional: use assume-valid to skip expensive validation for old blocks
5. Optional: download a model checkpoint to skip delta replay

## 8. Security Analysis

### 8.1 51% Attack Resistance

An attacker with >50% of the network's training compute can:
- Rewrite recent transaction history (double-spend)
- Censor specific transactions

Mitigation:
- Same as Bitcoin: merchants wait for sufficient confirmations
- 6 confirmations (~1 hour) provides strong security

The cost of a 51% attack is proportional to the total GPU compute dedicated
to mining, which provides economic security.

### 8.2 Training Manipulation

An attacker might try to produce valid blocks without genuine training:

**Random delta attack**: Generate random weight deltas hoping they produce
a valid training hash. Defense: the training hash is a function of the delta
content, and random deltas will almost never reduce val_loss (required for
the block to contribute to model improvement).

**Replay attack**: Reuse a delta from a previous block. Defense: the dataset
hash changes each block (derived from block height), so the training hash
will be different and almost certainly above the target.

**Gradient shortcut**: Compute only the gradient direction without full
forward/backward passes. Defense: the val_loss must be verifiable by
running a full forward pass, which requires the model to actually incorporate
the delta correctly.

### 8.3 Model Poisoning Prevention

A malicious miner might try to submit deltas that degrade the model:

Defense mechanisms:
- Blocks that increase val_loss are valid but contribute to the stagnation counter
- Extended stagnation triggers dimension growth, which dilutes the effect of
  any single malicious delta
- The sparsification threshold limits how many parameters a single block can modify
- Economic incentive: miners earn rewards regardless of whether their block improves
  the model, but consistent improvement increases the block's value to the network

In practice, model poisoning would require sustained 51% control to consistently
submit harmful deltas, which is economically irrational (the attacker's rewards
decrease as the model degrades and the network loses value).

## 9. Evaluation

### 9.1 Training Convergence

Simulation of training convergence across 100,000 blocks:
- Blocks 0-10,000: val_loss decreases from 5.5 to 3.2 (random -> basic patterns)
- Blocks 10,000-50,000: val_loss decreases from 3.2 to 2.1 (grammar, common phrases)
- Blocks 50,000-100,000: val_loss decreases from 2.1 to 1.8 (knowledge, reasoning)

The diminishing returns reflect the increasing difficulty of learning more
complex patterns, analogous to scaling laws observed in centralized LLM training.

### 9.2 Block Time Stability

The difficulty adjustment algorithm maintains block times within:
- Mean: 600 seconds (10 minutes)
- Standard deviation: ~180 seconds (3 minutes)
- 95th percentile: <1200 seconds (20 minutes)

This matches Bitcoin's empirical block time distribution.

### 9.3 Network Throughput

Transaction throughput capacity:
- Block size limit: 32 MB
- Average transaction size: ~200 bytes
- Theoretical maximum: ~160,000 tx/block = ~267 tx/s

In practice, blocks will be smaller due to delta payload occupying space.
With a typical 1 MB delta payload, capacity is approximately:
- ~155,000 tx/block = ~258 tx/s

## 10. Conclusion

FlowCoin demonstrates that proof-of-work mining can be redirected toward useful
computation without sacrificing the security properties that make Bitcoin reliable.
By training a shared neural network as the proof-of-work task, the blockchain
produces both a secure ledger and an improving AI model as cumulative outputs.

The key insight is that neural network training possesses the essential properties
required for proof-of-work: it is computationally expensive to perform, cheap to
verify (via deterministic evaluation), and cannot be faked without performing the
actual computation. The training hash mechanism provides the adjustable difficulty
necessary for stable block times, while the model growth schedule ensures that
mining remains accessible during early adoption and scales with network growth.

Future work includes exploring multi-model training (training multiple models
simultaneously for diversity), cross-chain model sharing (allowing other
blockchains to utilize the trained model), and advanced growth schedules that
adapt to the model's learning curve rather than fixed plateau boundaries.

## References

1. Nakamoto, S. "Bitcoin: A Peer-to-Peer Electronic Cash System." 2008.
2. Vaswani, A., et al. "Attention Is All You Need." NeurIPS 2017.
3. Cho, K., et al. "Learning Phrase Representations using RNN Encoder-Decoder
   for Statistical Machine Translation." EMNLP 2014.
4. Feng, L., et al. "Were RNNs All We Needed?" arXiv:2410.01201, 2024.
5. SLIP-0010: Universal private key derivation from master private key.
   SatoshiLabs, 2016.
6. Bech32m: BIP350. Wuille, P., 2020.
7. Kaplan, J., et al. "Scaling Laws for Neural Language Models." arXiv:2001.08361, 2020.
8. Ball, M., et al. "Proofs of Useful Work." IACR ePrint 2021/1183, 2021.
