# FlowCoin Economic Analysis

## Supply Curve

FlowCoin uses Bitcoin's exact monetary policy: 21 million coins with
a halving schedule every 210,000 blocks (~4 years).

### Emission Schedule

| Era | Blocks | Reward/Block | Era Total | Cumulative | % of Supply |
|-----|--------|-------------|-----------|------------|-------------|
| 0 | 0 - 209,999 | 50.0 FLOW | 10,500,000 | 10,500,000 | 50.00% |
| 1 | 210,000 - 419,999 | 25.0 FLOW | 5,250,000 | 15,750,000 | 75.00% |
| 2 | 420,000 - 629,999 | 12.5 FLOW | 2,625,000 | 18,375,000 | 87.50% |
| 3 | 630,000 - 839,999 | 6.25 FLOW | 1,312,500 | 19,687,500 | 93.75% |
| 4 | 840,000 - 1,049,999 | 3.125 FLOW | 656,250 | 20,343,750 | 96.88% |
| 5 | 1,050,000 - 1,259,999 | 1.5625 FLOW | 328,125 | 20,671,875 | 98.44% |
| 6 | 1,260,000 - 1,469,999 | 0.78125 FLOW | 164,062.5 | 20,835,937.5 | 99.22% |
| ... | ... | halves | ... | approaches 21M | 100% |

The supply is a geometric series:

```
Total = 210,000 * (50 + 25 + 12.5 + 6.25 + ...) = 210,000 * 100 = 21,000,000
```

### Supply Curve Properties

1. **Front-loaded**: 50% of all coins mined in the first ~4 years.
2. **Asymptotic**: Supply approaches but never reaches 21M.
3. **Deflationary**: The inflation rate decreases every halving.
4. **Predictable**: Every participant knows the exact emission schedule.

### Inflation Rate Over Time

| Year | Approx. Height | Annual New Coins | Approx. Supply | Inflation |
|------|----------------|------------------|----------------|-----------|
| 1 | 52,596 | 2,629,800 | 2,629,800 | N/A |
| 4 | 210,384 | 2,629,800 | 10,519,200 | 33.3% |
| 5 | 262,980 | 1,314,900 | 11,834,100 | 12.5% |
| 8 | 420,768 | 1,314,900 | 15,779,700 | 9.1% |
| 9 | 473,364 | 657,450 | 16,437,150 | 4.2% |
| 12 | 631,152 | 657,450 | 18,408,450 | 3.7% |
| 16 | 841,536 | 164,362 | 19,855,912 | 0.8% |
| 20 | 1,051,920 | 82,181 | 20,425,243 | 0.4% |

By year 20, annual inflation drops below 0.5%.

## Mining Economics: Data as Hashrate

In Bitcoin, hashrate is a function of electricity and ASIC hardware.
In FlowCoin, "hashrate" is a function of:

1. **Training data quality**: Better data produces lower validation loss,
   which produces training hashes more likely to meet the difficulty target.

2. **GPU compute**: More GPUs allow faster training iterations and
   more nonce attempts per unit time.

3. **Model expertise**: Understanding what data improves the model
   (curriculum design, data cleaning, augmentation) provides an edge
   analogous to ASIC efficiency gains.

### Cost Structure

| Component | Bitcoin | FlowCoin |
|-----------|---------|----------|
| Capital (hardware) | ASIC miners | GPUs |
| Recurring (energy) | Electricity | Electricity + data |
| Skill premium | Minimal | Significant |
| Output | Random hashes | Trained model |
| Network benefit | Security only | Security + knowledge |

### Mining Revenue Formula

```
Daily revenue = blocks_per_day * block_reward * (local_hashrate / network_hashrate)
             = 144 * reward * share
```

At genesis: 144 * 50 = 7,200 FLOW/day for the entire network.

## Self-Balancing Knowledge Market

FlowCoin creates a self-balancing market for knowledge through several
feedback mechanisms:

### Difficulty as Quality Selector

- When many miners compete, difficulty rises.
- Higher difficulty requires lower validation loss.
- Lower validation loss requires better training data and techniques.
- Only the most effective training improvements are profitable.

### Data Exhaustion and Natural Rotation

- Popular training data gets "used up": the model learns it quickly,
  and further training on the same data shows diminishing returns.
- This creates a natural rotation: miners must find novel data or
  novel training approaches to maintain profitability.
- The result is a broad, diverse model rather than one overfit to
  a single data source.

### Economic Incentive for Data Quality

```
profit = (block_reward * probability_of_winning) - (compute_cost + data_cost)
```

Since probability of winning depends on validation loss improvement:
- Bad data: high loss, low probability -> unprofitable.
- Good data: low loss, high probability -> profitable.

The market price of FLOW determines the equilibrium: when FLOW price
rises, more miners join, difficulty increases, and only the best
training is profitable.

## GPU Requirements Over Time

### Era 0 (Blocks 0-209,999)

- **Model size**: 32M - 3B parameters (grows continuously).
- **Early blocks**: A single consumer GPU (8 GB VRAM) suffices.
  The model is small (32M params = 128 MB float32) and difficulty
  is at minimum.
- **Later in era 0**: As the model grows and difficulty increases,
  multiple GPUs or professional hardware (A100, H100) provide
  an advantage.

### Era 1+ (Blocks 210,000+)

- **Model size**: 3B+ parameters.
- **Storage**: Model weights alone require 12+ GB in float32.
- **Training**: Gradient computation requires 2-3x model size in memory.
- **Practical minimum**: 24 GB VRAM GPU (RTX 4090, A5000).
- **Competitive mining**: Multi-GPU setups or cloud GPU clusters.

### Node Requirements (Non-Mining)

- **CPU**: x86-64 with SSE4.2 (consensus evaluation is CPU-only).
- **RAM**: 4 GB base + model size (starts at ~200 MB, grows to ~12 GB
  over the first 100K blocks).
- **Disk**: 1 GB base + ~3 GB per 100K blocks of chain data.
- **Network**: 1 Mbps symmetric minimum.

## Fee Market Development

### Phase 1: Subsidy-Dominated (Era 0-2)

Block reward is 12.5-50 FLOW. Fees are negligible relative to reward.
Transaction demand is low during network bootstrap.

Fee policy mirrors Bitcoin:
- Minimum relay fee: 1000 atomic units per KB (0.00001 FLOW/KB).
- Mempool limit: 300 MB.
- Replace-by-fee (RBF) supported.

### Phase 2: Fee Emergence (Era 3-5)

Block reward drops to 1.5-6.25 FLOW. As the network grows and model
value increases, transaction demand rises. Fees become a meaningful
portion of miner revenue.

### Phase 3: Fee-Dominated (Era 6+)

Block reward is below 1 FLOW. The network relies on transaction fees
for security, similar to Bitcoin's long-term model.

### Fee Estimation

FlowCoin uses a bucketed fee estimator similar to Bitcoin Core:
- Track fee rates of recently confirmed transactions.
- Bucket by fee rate (atomic units per byte).
- Estimate required fee for confirmation within N blocks.

## Comparison With Bitcoin and Ethereum Economics

| Property | Bitcoin | Ethereum | FlowCoin |
|----------|---------|----------|----------|
| Max supply | 21M | Unlimited | 21M |
| Consensus | PoW (SHA-256) | PoS | PoUT |
| Block time | 10 min | 12 sec | 10 min |
| Block reward | 6.25 BTC (2024) | ~2 ETH | 50 FLOW (genesis) |
| Halving | Every 210K blocks | N/A | Every 210K blocks |
| Useful work | No | No | Yes (training) |
| Energy waste | High | Low (PoS) | Moderate (GPU compute) |
| Hardware | ASICs | Validators | GPUs |
| Barrier to entry | Very high (ASICs) | 32 ETH stake | GPU + data |
| Network output | Security | Security + execution | Security + knowledge |

### Key Economic Differences

1. **FlowCoin produces a useful artifact**: The trained model has value
   independent of the currency. This creates a floor for the network's
   value proposition even if the token price is low.

2. **Data is the differentiator**: Unlike Bitcoin where all miners run
   the same algorithm, FlowCoin miners compete on data quality and
   training effectiveness. This creates a knowledge economy.

3. **GPU depreciation curve**: GPUs depreciate more slowly than ASICs
   and have resale value for other compute tasks. This lowers the
   effective cost of mining hardware.

4. **Same monetary policy as Bitcoin**: The familiar 21M supply cap
   and halving schedule provide economic predictability.

## Long-Term Value Proposition

### The Model as a Public Good

The consensus model is a globally shared, permissionless AI model:

- **No single owner**: The model belongs to the network.
- **Continuously improving**: Every block makes it better.
- **Censorship-resistant**: No entity can prevent model access.
- **Deterministic**: Every node has an identical copy.

### Value Accrual Mechanisms

1. **Token demand**: Using the model requires running a node, which
   validates transactions, which requires holding FLOW for fees.

2. **Mining economics**: Training the model requires spending FLOW
   (opportunity cost of compute), creating natural demand.

3. **Network effects**: As the model improves, more users want access,
   increasing transaction volume and fee revenue.

4. **Data market**: The implicit market for training data creates
   an economic ecosystem around the network.

### Network Effects and Adoption Curves

- **Phase 1 (Launch)**: Early adopters mine with consumer GPUs.
  Model quality is low but improving rapidly (steep learning curve).

- **Phase 2 (Growth)**: Model becomes useful for real tasks.
  Professional miners enter with better hardware and data.
  Model quality improves logarithmically.

- **Phase 3 (Maturity)**: Model reaches competitive quality.
  Mining becomes industrialized. Fee market develops.
  The network provides a unique value proposition: a decentralized,
  permissionless, continuously-trained AI model.

## Risk Factors

1. **GPU centralization**: If mining becomes dominated by a few
   large GPU clusters, it mirrors Bitcoin's ASIC centralization concern.

2. **Data monoculture**: If all miners train on the same data,
   the model overfits. The difficulty mechanism partially mitigates this
   (stale data produces diminishing returns).

3. **Model quality plateau**: The model may reach a quality ceiling
   where further training shows negligible improvement. At that point,
   mining becomes purely a security mechanism (like Bitcoin's PoW).

4. **Regulatory risk**: AI training may face regulatory scrutiny.
   The decentralized nature provides some resistance, but individual
   miners in regulated jurisdictions may face constraints.

5. **Competition**: Other projects may attempt similar approaches.
   First-mover advantage and network effects provide some moat.

## Token Utility

FLOW tokens serve multiple functions in the network:

### 1. Transaction Fees

Every transaction requires a fee paid in FLOW. Fees serve two purposes:
- **Spam prevention**: Minimum relay fee (0.00001 FLOW/KB) prevents
  denial-of-service through transaction flooding.
- **Miner compensation**: After block rewards diminish, fees become
  the primary incentive for miners to secure the network.

### 2. Mining Collateral

Miners must invest compute resources (GPUs, electricity, data) to
produce valid training deltas. The expected FLOW reward must exceed
these costs for mining to be profitable. This creates an implicit
collateral requirement: miners stake their compute costs against
the probability of earning block rewards.

### 3. Model Access Token

While the model weights are public (every node has a copy), practical
use of the model for inference requires running a FlowCoin node.
Running a node requires participating in the network, which means
processing transactions and paying fees for any on-chain operations.

### 4. Governance Signal

Token holders can signal preferences through:
- **Mining participation**: Choosing what data to train on implicitly
  guides the model's development direction.
- **Fee market behavior**: Willingness to pay fees signals demand for
  different types of transactions or model capabilities.

## Game Theory

### Miner Incentives

A rational miner maximizes:

```
E[profit] = P(win) * reward - cost_compute - cost_data - cost_energy
```

Where P(win) depends on:
- Validation loss improvement (better training -> lower loss -> better hash)
- Network difficulty (more miners -> lower win probability)
- Hardware efficiency (faster training -> more attempts per unit time)

### Selfish Mining

The "selfish mining" attack (withholding blocks) applies to FlowCoin
as it does to Bitcoin. However, in FlowCoin, withholding blocks also
means withholding training improvements. A selfish miner would be
training on a stale model (without others' improvements), which is
slightly disadvantageous for producing good future blocks.

### 51% Attack

A miner controlling >51% of training compute could:
- Rewrite chain history (double-spend)
- Censor transactions
- Degrade model quality intentionally

The cost of a 51% attack is the compute required to out-train all
other miners, which scales with total network GPU power.

### Data Poisoning

A malicious miner could try to submit training deltas that deliberately
degrade the model. Defenses:

1. **Check 6-7**: val_loss must be finite and below MAX_VAL_LOSS.
2. **Check 9**: val_loss cannot increase by more than 2x from parent.
3. **Check 15**: Forward evaluation verifies the claimed loss.
4. **Difficulty**: Bad deltas produce high-entropy training hashes
   that are unlikely to meet the difficulty target.

### Free-Rider Problem

Nodes benefit from the trained model without mining. This is by design:
- Full nodes provide network security by validating blocks.
- SPV nodes provide demand for the token (transactions + fees).
- The model is a positive externality that increases network value.

## Market Dynamics

### Price Discovery

FLOW price is determined by supply and demand:

**Supply side**:
- Fixed, predictable emission schedule.
- Miners sell to cover operational costs.
- No pre-mine, no ICO, no venture allocation.

**Demand side**:
- Transaction fees for on-chain operations.
- Speculation on future model value.
- Mining revenue reinvestment.
- Model access (running inference on the network model).

### Mining Profitability Equilibrium

Mining reaches equilibrium when:

```
marginal_cost_of_mining = expected_revenue_per_block * P(winning)
```

If FLOW price rises:
1. Mining becomes more profitable.
2. More miners join (difficulty increases).
3. Each miner's share decreases.
4. Equilibrium restores at higher total compute.

If FLOW price falls:
1. Mining becomes less profitable.
2. Marginal miners exit (difficulty decreases).
3. Remaining miners' shares increase.
4. Equilibrium restores at lower total compute.

### Data Economy

FlowCoin creates a derivative data economy:

- **Data providers**: Sell or license training data to miners.
- **Training specialists**: Offer expertise in curriculum design.
- **Model consumers**: Use the consensus model for inference tasks.
- **Infrastructure providers**: Offer GPU cloud services for miners.

This ecosystem exists without any on-chain marketplace -- it emerges
naturally from the incentive structure.

## Comparison With Proof-of-Stake Economics

| Property | Proof-of-Stake | Proof-of-Training |
|----------|---------------|-------------------|
| Capital type | Financial (tokens) | Physical (GPUs + data) |
| Lock-up | Token staking | Compute commitment |
| Slashing | Token destruction | Wasted compute |
| Centralization risk | Wealth concentration | GPU concentration |
| Energy use | Very low | Moderate |
| Useful output | None | Trained model |
| Barrier to entry | Capital requirement | Hardware + expertise |
| Validator income | Proportional to stake | Proportional to training quality |

### Key Advantage Over PoS

In Proof-of-Stake, capital compounds: staking rewards increase the
stake, which increases future rewards. This creates a rich-get-richer
dynamic.

In Proof-of-Training, hardware depreciates and data ages. There is no
compounding effect: yesterday's training does not make today's training
easier. Each block requires fresh, useful compute work. This provides
more equitable long-term access to block rewards.

## Detailed Cost Analysis

### Mining Cost Breakdown (Era 0, Year 1)

Assumptions: 1 FLOW = $1.00 USD (illustrative)

| Cost Component | Monthly | % of Total |
|----------------|---------|------------|
| GPU hardware (amortized 3y) | $800 | 40% |
| Electricity (8 GPUs x 350W) | $420 | 21% |
| Internet bandwidth (100 Mbps) | $100 | 5% |
| Data acquisition/licensing | $200 | 10% |
| Server hosting/cooling | $300 | 15% |
| Storage (model + chain data) | $50 | 2.5% |
| Maintenance and monitoring | $130 | 6.5% |
| **Total** | **$2,000** | **100%** |

Expected revenue (1% of network hashrate):
- 144 blocks/day * 50 FLOW * 1% = 72 FLOW/day
- 72 * 30 = 2,160 FLOW/month = $2,160/month

Profit margin: ~8% (thin margin encourages efficiency competition).

### Break-Even Analysis

The break-even FLOW price for a mining operation depends on:

```
break_even_price = monthly_cost / (blocks_per_month * reward * share)
                 = $2,000 / (4,320 * 50 * 0.01)
                 = $2,000 / 2,160
                 = $0.93 per FLOW
```

If FLOW trades above $0.93, the operation is profitable.
If below, rational miners exit, difficulty drops, and remaining
miners' shares increase until equilibrium is restored.

### Hardware ROI Timeline

| GPU Model | Cost | Hash Equivalent | Payback Period |
|-----------|------|-----------------|----------------|
| RTX 4090 | $1,600 | High | 6-12 months |
| RTX 4080 | $1,200 | Medium-High | 8-14 months |
| RTX 3090 | $800 | Medium | 10-16 months |
| A100 80GB | $10,000 | Very High | 12-18 months |
| H100 80GB | $25,000 | Highest | 18-24 months |

Unlike ASICs, GPUs retain resale value for gaming, rendering,
and general-purpose AI workloads.

## Treasury and Funding Model

FlowCoin has no pre-mine, no ICO, no developer tax, and no treasury.
Development is funded through:

1. **Voluntary donations**: Community members donate to development.
2. **Mining participation**: Core developers may mine.
3. **Service provision**: Development team may offer consulting,
   hosted mining, or model inference services.
4. **Grants**: External grants from AI research organizations.

This mirrors Bitcoin's funding model and avoids the governance
complexity of treasury-funded protocols.

## Long-Term Monetary Properties

### Store of Value

FlowCoin's monetary properties support store-of-value characteristics:

1. **Scarcity**: Fixed 21M supply cap, no inflation after emission.
2. **Durability**: Digital, no physical degradation.
3. **Divisibility**: 8 decimal places (satoshi-level granularity).
4. **Portability**: Transferable globally via the internet.
5. **Fungibility**: Each FLOW is interchangeable.
6. **Verifiability**: Open-source validation of all properties.

### Medium of Exchange

Transaction characteristics:

| Property | Value |
|----------|-------|
| Confirmation time | ~10 minutes (1 block) |
| Final settlement | ~60 minutes (6 blocks) |
| Max throughput | ~7 tx/s (similar to Bitcoin) |
| Transaction cost | ~0.00001-0.001 FLOW |
| Privacy | Pseudonymous (public addresses) |

### Unit of Account

FLOW denomination units:

| Unit | Atomic Units | FLOW |
|------|-------------|------|
| 1 FLOW | 100,000,000 | 1.00000000 |
| 1 mFLOW | 100,000 | 0.00100000 |
| 1 uFLOW | 100 | 0.00000100 |
| 1 sat | 1 | 0.00000001 |

## Network Security Budget

The security budget is the total value paid to miners (block rewards + fees).
This determines the cost of attacking the network:

| Year | Block Reward | Est. Fees | Security Budget/Year |
|------|-------------|-----------|---------------------|
| 1 | 50 FLOW | ~0 | ~2.6M FLOW |
| 5 | 25 FLOW | ~1 FLOW | ~1.4M FLOW |
| 9 | 12.5 FLOW | ~5 FLOW | ~920K FLOW |
| 13 | 6.25 FLOW | ~10 FLOW | ~850K FLOW |
| 17 | 3.125 FLOW | ~20 FLOW | ~1.2M FLOW |
| 21 | 1.5625 FLOW | ~40 FLOW | ~2.2M FLOW |

In the long term (era 6+), the security budget depends entirely
on fee revenue. A healthy fee market is essential for long-term
network security.

## Model Valuation

The consensus model has value independent of the FLOW token:

### As a Public Good

- The model provides general-purpose AI capabilities.
- Access is permissionless: anyone running a node has a copy.
- No API keys, no rate limits, no censorship.

### Valuation Approaches

1. **Replacement cost**: What would it cost to train an equivalent
   model from scratch? At 100K blocks of training: estimated
   $10-100M in GPU compute at market rates.

2. **Revenue potential**: If the model were a commercial API,
   what revenue could it generate? Comparable to mid-tier
   language models: $10-50M/year.

3. **Network premium**: The model's value accrues to the FLOW
   token through network effects. Token market cap should
   reflect both monetary and model value.
