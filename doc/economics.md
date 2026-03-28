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

## Mining Economics

FlowCoin uses Keccak-256d Proof-of-Work, where hashrate is a function of
GPU compute power and electricity cost. The larger internal state of
Keccak (1600-bit vs SHA-256's 256-bit) naturally favors general-purpose
GPU hardware over custom ASICs.

### Cost Structure

| Component | Bitcoin | FlowCoin |
|-----------|---------|----------|
| Capital (hardware) | ASIC miners | GPUs |
| Recurring (energy) | Electricity | Electricity |
| Output | SHA-256d hashes | Keccak-256d hashes |
| Network benefit | Security | Security |

### Mining Revenue Formula

```
Daily revenue = blocks_per_day * block_reward * (local_hashrate / network_hashrate)
             = 144 * reward * share
```

At genesis: 144 * 50 = 7,200 FLOW/day for the entire network.

## GPU Requirements Over Time

### Era 0 (Blocks 0-209,999)

- **Early blocks**: A single consumer GPU suffices. Difficulty is
  at minimum, so even modest GPUs can find blocks.
- **Later in era 0**: As difficulty increases with more miners,
  higher-end GPUs provide an advantage.

### Era 1+ (Blocks 210,000+)

- **Competitive mining**: Multiple high-end GPUs or cloud GPU clusters.
- As difficulty rises, only efficient operations remain profitable.

### Node Requirements (Non-Mining)

- **CPU**: x86-64 with SSE4.2.
- **RAM**: 4 GB minimum.
- **Disk**: 1 GB base + ~1 GB per 100K blocks of chain data.
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

Block reward drops to 1.5-6.25 FLC. As the network grows,
transaction demand rises. Fees become a meaningful portion of
miner revenue.

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
| Consensus | PoW (SHA-256d) | PoS | PoW (Keccak-256d) |
| Block time | 10 min | 12 sec | 10 min |
| Block reward | 6.25 BTC (2024) | ~2 ETH | 50 FLC (genesis) |
| Halving | Every 210K blocks | N/A | Every 210K blocks |
| Hardware | ASICs | Validators | GPUs |
| Barrier to entry | Very high (ASICs) | 32 ETH stake | Consumer GPU |

### Key Economic Differences

1. **GPU mining**: Keccak-256d's large internal state (1600 bits)
   naturally favors general-purpose GPU hardware over custom ASICs,
   keeping mining more accessible.

2. **GPU depreciation curve**: GPUs depreciate more slowly than ASICs
   and have resale value for other compute tasks. This lowers the
   effective cost of mining hardware.

3. **Same monetary policy as Bitcoin**: The familiar 21M supply cap
   and halving schedule provide economic predictability.

## Long-Term Value Proposition

### Value Accrual Mechanisms

1. **Token demand**: Using the network requires holding FLC for fees.

2. **Mining economics**: Mining requires GPU compute investment,
   creating natural demand for the token.

3. **Network effects**: As adoption grows, transaction volume
   and fee revenue increase.

## Risk Factors

1. **GPU centralization**: If mining becomes dominated by a few
   large GPU clusters, it mirrors Bitcoin's ASIC centralization concern.

2. **Competition**: Other Keccak-based or GPU-mineable projects may
   compete for hashrate. Network effects provide some moat.

## Token Utility

FLOW tokens serve multiple functions in the network:

### 1. Transaction Fees

Every transaction requires a fee paid in FLOW. Fees serve two purposes:
- **Spam prevention**: Minimum relay fee (0.00001 FLOW/KB) prevents
  denial-of-service through transaction flooding.
- **Miner compensation**: After block rewards diminish, fees become
  the primary incentive for miners to secure the network.

### 2. Mining Collateral

Miners must invest compute resources (GPUs, electricity) to find
valid proof-of-work. The expected FLC reward must exceed these costs
for mining to be profitable. This creates an implicit collateral
requirement: miners stake their compute costs against the probability
of earning block rewards.

## Game Theory

### Miner Incentives

A rational miner maximizes:

```
E[profit] = P(win) * reward - cost_compute - cost_data - cost_energy
```

Where P(win) depends on:
- Hashrate (more Keccak-256d hashes per second -> higher probability)
- Network difficulty (more miners -> lower win probability)
- Hardware efficiency (better GPU -> more hashes per watt)

### Selfish Mining

The "selfish mining" attack (withholding blocks) applies to FlowCoin
as it does to Bitcoin. The same analysis and mitigations apply.

### 51% Attack

A miner controlling >51% of the network hashrate could:
- Rewrite chain history (double-spend)
- Censor transactions

The cost of a 51% attack is the hashrate required to exceed all
other miners, which scales with total network GPU power.

### Free-Rider Problem

Nodes benefit from the network without mining. This is by design:
- Full nodes provide network security by validating blocks.
- SPV nodes provide demand for the token (transactions + fees).

## Market Dynamics

### Price Discovery

FLOW price is determined by supply and demand:

**Supply side**:
- Fixed, predictable emission schedule.
- Miners sell to cover operational costs.
- No pre-mine, no ICO, no venture allocation.

**Demand side**:
- Transaction fees for on-chain operations.
- Speculation on future value.
- Mining revenue reinvestment.

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

## Comparison With Proof-of-Stake Economics

| Property | Proof-of-Stake | Proof-of-Work (FlowCoin) |
|----------|---------------|--------------------------|
| Capital type | Financial (tokens) | Physical (GPUs) |
| Lock-up | Token staking | Compute commitment |
| Slashing | Token destruction | Wasted compute |
| Centralization risk | Wealth concentration | GPU concentration |
| Energy use | Very low | Moderate |
| Barrier to entry | Capital requirement | Hardware |
| Validator income | Proportional to stake | Proportional to hashrate |

### Key Advantage Over PoS

In Proof-of-Stake, capital compounds: staking rewards increase the
stake, which increases future rewards. This creates a rich-get-richer
dynamic.

In Proof-of-Work, hardware depreciates. There is no compounding effect:
yesterday's hashing does not make today's hashing easier. Each block
requires fresh compute work. This provides more equitable long-term
access to block rewards.

## Detailed Cost Analysis

### Mining Cost Breakdown (Era 0, Year 1)

Assumptions: 1 FLOW = $1.00 USD (illustrative)

| Cost Component | Monthly | % of Total |
|----------------|---------|------------|
| GPU hardware (amortized 3y) | $800 | 44% |
| Electricity (8 GPUs x 350W) | $420 | 23% |
| Internet bandwidth (100 Mbps) | $100 | 5.5% |
| Server hosting/cooling | $300 | 16.5% |
| Storage (chain data) | $50 | 2.7% |
| Maintenance and monitoring | $130 | 7.1% |
| **Total** | **$1,800** | **100%** |

Expected revenue (1% of network hashrate):
- 144 blocks/day * 50 FLC * 1% = 72 FLC/day
- 72 * 30 = 2,160 FLC/month = $2,160/month

Profit margin: ~17% (thin margin encourages efficiency competition).

### Break-Even Analysis

The break-even FLC price for a mining operation depends on:

```
break_even_price = monthly_cost / (blocks_per_month * reward * share)
                 = $1,800 / (4,320 * 50 * 0.01)
                 = $1,800 / 2,160
                 = $0.83 per FLC
```

If FLC trades above $0.83, the operation is profitable.
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
3. **Service provision**: Development team may offer consulting
   or hosted mining services.
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

