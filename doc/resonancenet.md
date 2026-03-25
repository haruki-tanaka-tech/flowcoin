# ResonanceNet V5 Architecture

## Why Not Transformer?

Standard Transformers use self-attention with O(n^2) complexity in sequence
length. For a blockchain consensus model that must be evaluated deterministically
on every node, this quadratic cost is prohibitive:

- At seq_len=256, self-attention requires 65,536 operations per head per layer.
- Memory scales quadratically with context length.
- Causal masking adds implementation complexity for deterministic evaluation.

ResonanceNet V5 achieves O(1) per-token inference through three mechanisms:
1. **minGRU** replaces self-attention with a recurrent gate (O(d_model) per token).
2. **Slot memory** provides long-range recall with top-k routing (O(k) per token).
3. **Multi-scale convolution** captures local patterns (O(kernel_size) per token).

The result: inference cost is constant regardless of context length, making
it feasible for every node to evaluate the model as part of consensus.

## Architecture Components

### Token Embedding

```
input: byte token t in [0, 255]
output: x = tok_emb[t]    # shape [d_model]
```

Byte-level tokenization (vocab=256) avoids BPE complexity and ensures
every byte sequence is valid input. The embedding matrix `tok_emb` has
shape [256, d_model] and is weight-tied with the output projection
(see Weight Tying below).

### Layer Stack

Each of the `n_layers` layers applies four sub-blocks in sequence:

```
x = x + MultiScaleConv(RMSNorm(x))
x = x + MinGRU(RMSNorm(x))
x = x + SlotMemory(RMSNorm(x))
x = x + SwiGLU_FFN(RMSNorm(x))
```

Every sub-block uses pre-norm (RMSNorm before the operation) and
residual connections (add the output back to the input).

### MinGRU

The minimal gated recurrent unit computes:

```
z = sigmoid(W_z @ x + b_z)       # gate: which parts to update
h_tilde = tanh(W_h @ x + b_h)    # candidate: what to write
h = (1 - z) * h_prev + z * h_tilde   # interpolation
```

Parameters per layer:
- `gru_wz`: [d_model, d_model] -- gate weights
- `gru_wh`: [d_model, d_model] -- candidate weights
- `gru_bz`: [d_model] -- gate bias
- `gru_bh`: [d_model] -- candidate bias

Total: 2 * d_model^2 + 2 * d_model parameters.

The hidden state `h` persists across tokens, giving the model memory
of the entire sequence without attention. Inference is O(d_model^2) per
token regardless of sequence length.

### Slot Memory

Slot memory provides long-range associative recall via key-value lookup:

```
q = W_q @ x                      # query projection: [d_model]
scores = slot_keys^T @ q          # attention over all slots: [n_slots]
top_k_idx = argmax_k(scores)      # select top-k slots (k=2)
values = slot_values[:, top_k_idx]  # retrieve top-k values
weighted = softmax(scores[top_k_idx]) @ values^T  # weighted sum
output = W_out @ weighted         # output projection: [d_model]
```

Parameters per layer:
- `slot_keys`: [d_model, n_slots] -- slot key vectors
- `slot_values`: [d_model, n_slots] -- slot value vectors
- `slot_proj_q`: [d_model, d_model] -- query projection
- `slot_proj_out`: [d_model, d_model] -- output projection

Total: 2 * d_model * n_slots + 2 * d_model^2 parameters.

Only the top-k=2 slots are active per token, so inference cost is
O(d_model * n_slots) for the score computation but O(d_model * k) for
the value retrieval. Since k is fixed at 2, the retrieval is O(1) in
terms of slot count. The score computation uses a single matrix-vector
multiply which is parallelizable.

### Multi-Scale Causal Convolution

Three depthwise causal convolutions with kernels 3, 7, and 15 capture
patterns at different scales:

```
c3  = causal_depthwise_conv(x, kernel=3)   # local trigrams
c7  = causal_depthwise_conv(x, kernel=7)   # phrase-level
c15 = causal_depthwise_conv(x, kernel=15)  # clause-level
combined = c3 + c7 + c15                    # sum all scales
output = W_mix @ combined                   # mix: [d_model, d_model]
```

Parameters per layer:
- `conv3_w`: [3, d_model] -- kernel=3 depthwise weights
- `conv7_w`: [7, d_model] -- kernel=7 depthwise weights
- `conv15_w`: [15, d_model] -- kernel=15 depthwise weights
- `conv_mix_w`: [d_model, d_model] -- mixing projection

Total: 25 * d_model + d_model^2 parameters.

Causal padding ensures no future information leaks into the current token.
Depthwise convolution (each channel convolved independently) keeps the
parameter count linear in d_model.

### SwiGLU FFN

The feed-forward network uses SwiGLU activation:

```
gate = W_gate @ x                 # [d_model -> d_ff]
up   = W_up @ x                   # [d_model -> d_ff]
activated = silu(gate) * up        # element-wise: gated activation
output = W_down @ activated        # [d_ff -> d_model]
```

Where `silu(x) = x * sigmoid(x)` (also called Swish).

Parameters per layer:
- `ffn_gate_w`: [d_model, d_ff] -- gate projection
- `ffn_up_w`: [d_model, d_ff] -- up projection
- `ffn_down_w`: [d_ff, d_model] -- down projection

Total: 3 * d_model * d_ff parameters.

With d_ff = 2 * d_model, this is 6 * d_model^2 per layer.

### RMSNorm

Root Mean Square normalization (simpler than LayerNorm, no mean subtraction):

```
rms = sqrt(mean(x^2) + epsilon)
output = (x / rms) * w           # w is a learned scale: [d_model]
```

Why not LayerNorm? RMSNorm:
- Has fewer parameters (no bias, no learned mean).
- Is faster to compute (one fewer reduction operation).
- Produces identical results to LayerNorm when the input mean is near zero,
  which is typical after residual connections.
- Is deterministic without the subtraction step that can cause
  floating-point ordering issues.

Parameters: `w` has shape [d_model]. Each layer has 4 RMSNorm instances
(one before each sub-block), plus one final norm after the last layer.

Total RMSNorm parameters: (4 * n_layers + 1) * d_model.

### Weight Tying

The output projection (logits computation) reuses the token embedding:

```
logits = tok_emb^T @ final_norm(h)   # [vocab, d_model] @ [d_model] -> [vocab]
```

This saves `vocab * d_model` parameters (65,536 at genesis) and provides
a natural relationship between input and output token representations.

## Deterministic Evaluation

Consensus requires every node to compute identical results for identical
inputs. ResonanceNet V5 guarantees this through:

1. **Single thread**: All evaluation runs on one CPU thread. No SIMD,
   no multi-threading, no GPU. This eliminates hardware-dependent
   floating-point reordering.

2. **Float32 only**: All weights and activations are IEEE 754 float32.
   No mixed precision, no bfloat16, no quantization during evaluation.

3. **Fixed accumulation order**: Matrix multiplications use explicit
   row-major accumulation. No parallel reduction, no fused multiply-add
   unless the compiler guarantees bit-identical results.

4. **No `-ffast-math`**: The build system explicitly omits this flag
   to preserve IEEE 754 semantics (NaN propagation, denormal handling,
   signed zero, etc.).

5. **Deterministic activation functions**: `sigmoid`, `tanh`, `silu`
   use the standard library implementations with no approximations.

## Growth Schedule

The model grows continuously -- every block adds parameters:

### Dimension Growth (Linear, Then Freeze)

```
d_model(h) = min(512 + h, 1024)
n_layers(h) = min(8 + h/32, 24)
d_ff(h) = 2 * d_model(h)
n_heads(h) = d_model(h) / 64
gru_dim(h) = d_model(h)
```

Dimensions freeze at height 512 (d_model reaches 1024).
After that, only slots grow.

### Slot Growth (Unbounded)

```
n_slots(h) = 1024 + h * 4
```

No cap on slots. The model accumulates knowledge forever:

| Height | n_slots | Approx. Params |
|--------|---------|----------------|
| 0 | 1,024 | ~50M |
| 1,000 | 5,024 | ~80M |
| 10,000 | 41,024 | ~350M |
| 100,000 | 401,024 | ~3B |
| 1,000,000 | 4,001,024 | ~30B |

Inference remains O(1) because only top_k=2 slots are active per token.

### How New Dimensions Are Initialized

When `expand_to(new_dims)` is called:

1. New embedding rows are zero-initialized.
2. New weight matrix rows/columns are zero-initialized.
3. Existing weights are copied into the top-left submatrix.
4. The model hash changes (weights changed).

Zero initialization means the new dimensions contribute nothing initially.
Training naturally assigns values to them over subsequent blocks.

### How New Slots Are Initialized

New slot keys and values are zero-initialized. Since dot products with
zero vectors produce zero scores, new slots are never selected by top-k
until miners train them to have meaningful key vectors.

## Training vs. Inference

| Aspect | Training (Miner) | Inference (Validation) |
|--------|-------------------|------------------------|
| Threading | Multi-threaded OK | Single-threaded only |
| Precision | Float32 or mixed | Float32 only |
| Data | Miner's training corpus | Deterministic validation set |
| Gradient | Yes (backpropagation) | No (forward only) |
| Output | Weight delta | Cross-entropy loss |
| Duration | Minutes to hours | Seconds |

Miners can use any training framework, any data, any optimization
algorithm. The only consensus-critical operation is the forward
evaluation on the validation dataset, which must be deterministic.

## Comparison With Other Architectures

| Architecture | Attention | Per-Token Cost | Long-Range | Growth |
|-------------|-----------|----------------|------------|--------|
| Transformer | O(n^2) | O(n * d^2) | Full | Static |
| Linear Attention | O(n) | O(d^2) | Approximate | Static |
| Mamba (SSM) | O(n) | O(d * state) | Via state | Static |
| RWKV | O(n) | O(d^2) | Via WKV | Static |
| ResonanceNet V5 | O(1) | O(d^2 + d*k) | Slots + GRU | Continuous |

Key advantages of ResonanceNet V5 for blockchain consensus:

1. **O(1) per-token**: No dependency on sequence length.
2. **Deterministic**: Single-thread float32 produces identical results everywhere.
3. **Growable**: Slot memory grows without architectural changes.
4. **Separable**: Training and evaluation are cleanly separated.

## Parameter Count Formula

Total parameters = embedding + layers + final_norm

```
embedding = vocab * d_model                          # weight-tied
per_layer = 4 * d_model                              # 4x RMSNorm
          + (3 + 7 + 15) * d_model + d_model^2       # convolutions
          + 2 * d_model^2 + 2 * d_model               # minGRU
          + 2 * d_model * n_slots + 2 * d_model^2     # slot memory
          + 3 * d_model * d_ff                         # SwiGLU FFN
final_norm = d_model

total = embedding + n_layers * per_layer + final_norm
```

At genesis (d_model=512, n_layers=8, n_slots=1024, d_ff=1024):

```
embedding  = 256 * 512 = 131,072
per_layer  = 2,048 + 25*512 + 262,144 + 524,288 + 2*512 + 2*512*1024 + 524,288 + 3*512*1024
           = 2,048 + 12,800 + 262,144 + 524,288 + 1,024 + 1,048,576 + 524,288 + 1,572,864
           = 3,948,032
total      = 131,072 + 8 * 3,948,032 + 512
           = 131,072 + 31,584,256 + 512
           = 31,715,840 (~32M parameters)
```

## Implementation Notes

### ggml Integration

All tensor operations are implemented using ggml, a minimal C tensor library.
ggml provides:

- Static computation graphs (no dynamic dispatch overhead).
- CPU-only execution (no GPU dependency).
- Fixed memory allocation (pre-computed context size).
- No external dependencies.

The consensus model allocates a single ggml context with pre-computed
memory requirements. All tensors are created in this context and persist
for the lifetime of the model.

### Quantization

For storage efficiency, model weights can be quantized to int8:

```
For each tensor:
  scale = max(abs(weights)) / 127
  zero_point = 0
  quantized = round(weights / scale)
  packed = [scale:float32][zero_point:int8][data:int8*N]
```

Quantization is used only for storage and network transfer. All consensus
evaluation uses full float32 precision.

### Delta Format

Weight updates are stored as sparse deltas:

```
Sparse: [n_nonzero:uint32][index:uint32, value:float32] * n_nonzero
Dense:  [value:float32] * total_params
```

Both formats are zstd-compressed before inclusion in a block.
Typical compression ratios: 5-20x for sparse deltas.

## Training Strategy Considerations

### Data Selection

Miners must choose training data carefully. The consensus validation
dataset is fixed (deterministic Keccak-256 PRNG output), so the model
is evaluated on pseudo-random byte sequences. This means:

- **General-purpose training data is best**: Data that teaches the model
  general byte-level patterns (text, code, structured data) will reduce
  loss on the random validation set more effectively than narrow data.

- **Data diversity matters**: Training on a single domain (e.g., only
  English text) will improve performance on that domain but may not
  generalize well to the random validation set.

- **Diminishing returns**: As the model trains on more data, each
  additional training sample provides less loss reduction. Miners
  must continuously find novel, high-quality data.

### Learning Rate and Batch Size

Consensus limits the learning rate (max 0.0001) and batch size
(32-512 tokens) to prevent destructive weight updates:

- Too high a learning rate can increase val_loss, which is rejected
  by Check 9 (MAX_LOSS_INCREASE = 2.0).
- Excessively large batches may overfit to specific patterns.
- The sweet spot depends on the current model size and training stage.

### Sparsification Strategy

Miners can control delta sparsity by setting a sparsification threshold.
Higher thresholds produce sparser deltas (smaller compressed size) but
may discard useful weight updates. The trade-off:

- **Dense deltas**: Maximum training impact but large block size.
- **Sparse deltas**: Smaller blocks but potentially less effective training.
- **Optimal threshold**: Depends on the distribution of weight updates.
  Typically, a threshold that keeps 10-30% of weights non-zero provides
  good compression without significant quality loss.

### Multi-GPU Training

Miners with multiple GPUs can parallelize training:

1. **Data parallelism**: Split training data across GPUs, average gradients.
2. **Nonce parallelism**: Try different nonces on different GPUs.
3. **Curriculum search**: Different GPUs try different data mixtures
   to find the optimal training curriculum.

The consensus model must be evaluated on a single CPU thread, but
training can use any parallelism strategy.

## Evaluation Metrics

### Consensus-Critical: Cross-Entropy Loss

The only consensus-critical metric is the cross-entropy loss on the
validation dataset:

```
loss = -1/N * sum(log(P(x_i | x_1..x_{i-1})))
```

Where N is the number of tokens and P is the model's predicted
probability for the correct next token.

### Non-Consensus Metrics

For monitoring and debugging:

| Metric | Formula | Interpretation |
|--------|---------|----------------|
| Perplexity | exp(loss) | Average branching factor |
| Bits per byte | loss / ln(2) | Compression efficiency |
| Top-1 accuracy | correct / total | Fraction of correct predictions |
| Top-5 accuracy | in_top5 / total | Fraction in top 5 predictions |

### Baseline Values

| Model State | Typical Loss | Perplexity | Bits/Byte |
|-------------|-------------|------------|-----------|
| Random (untrained) | 5.545 | 256.0 | 8.0 |
| Genesis (seed=42) | ~5.5 | ~245 | ~7.9 |
| After 1000 blocks | ~4.5 | ~90 | ~6.5 |
| After 10000 blocks | ~3.5 | ~33 | ~5.0 |
| Mature model | ~2.5 | ~12 | ~3.6 |

## Memory Management

### ggml Context Sizing

The ggml context is pre-allocated with enough memory for all tensors:

```
context_size = embedding_size
             + n_layers * layer_size
             + final_norm_size
             + overhead (alignment, tensor headers)

embedding_size = vocab * d_model * sizeof(float)
layer_size = (RMSNorm weights + conv weights + GRU weights
             + slot weights + FFN weights) * sizeof(float)
overhead = n_tensors * 256  // ggml tensor header + alignment
```

### Weight Buffer Management

During delta application:

1. Decompress delta into a temporary float buffer.
2. Element-wise add to existing weights (in-place).
3. Free temporary buffer.

During model expansion:

1. Allocate new ggml context with larger dimensions.
2. Copy existing weights into new tensors (zero-padded).
3. Free old context.

Peak memory: 2x model size during expansion (old + new context).

### Delta History

The last 10 deltas are kept in a circular buffer for reorg support.
Each delta record stores the decompressed float vector and the height.
Memory cost: 10 * total_params * sizeof(float).

At genesis: 10 * 32M * 4 = 1.28 GB (can be reduced by storing compressed).

## Wire Format Details

### Delta Payload in Block

```
Block body:
  [CompactSize: n_transactions]
  [Transaction[0] .. Transaction[n-1]]
  [delta_payload: compressed bytes]

Header references:
  delta_offset:  byte offset of delta_payload from start of body
  delta_length:  uncompressed size of delta (for validation)
  sparse_count:  number of non-zero elements (for info)
  sparse_threshold: sparsification threshold used
```

### Sparse Delta Wire Format

```
[4 bytes: n_nonzero (uint32_t, LE)]
[n_nonzero entries:]
  [4 bytes: index (uint32_t, LE)]
  [4 bytes: value (float32, IEEE 754)]
```

Indices must be sorted ascending with no duplicates.
Values must be finite (no NaN, no Inf).
Indices must be in range [0, total_params).

### Dense Delta Wire Format

```
[total_params * 4 bytes: float32 values (IEEE 754)]
```

All values must be finite.

The format (sparse vs dense) is auto-detected from the decompressed size:
- If decompressed_size == 4 + n * 8 for some n, and the first 4 bytes
  encode n, it is sparse.
- Otherwise it is dense.

## Activation Function Details

### SiLU (Swish)

```
silu(x) = x * sigmoid(x) = x / (1 + exp(-x))
```

Properties:
- Smooth, non-monotonic.
- Self-gated: output depends on the input magnitude.
- Gradient: silu'(x) = sigmoid(x) * (1 + x * (1 - sigmoid(x))).
- Avoids the "dying ReLU" problem.

Used in the SwiGLU FFN gate projection.

### Sigmoid

```
sigmoid(x) = 1 / (1 + exp(-x))
```

Used in the minGRU gate computation.
Range: (0, 1). Output near 0 preserves previous state,
output near 1 overwrites with candidate.

### Tanh

```
tanh(x) = (exp(x) - exp(-x)) / (exp(x) + exp(-x))
```

Used in the minGRU candidate computation.
Range: (-1, 1). Normalizes candidate values to prevent
unbounded growth of the hidden state.

## Numerical Stability

### Softmax Stability

The softmax in slot memory uses the log-sum-exp trick:

```
max_val = max(scores)
log_sum = log(sum(exp(scores - max_val)))
probs[i] = exp(scores[i] - max_val - log_sum)
```

This prevents overflow when scores are large positive values
and underflow when scores are large negative values.

### RMSNorm Epsilon

RMSNorm uses epsilon = 1e-8 to prevent division by zero:

```
rms = sqrt(mean(x^2) + 1e-8)
```

This is critical for determinism: without epsilon, zero-input
could produce NaN on some implementations.

### Float32 Precision Limits

With float32 (23-bit mantissa):
- Relative precision: ~7 decimal digits.
- Smallest representable diff from 1.0: ~1.2e-7.
- Largest finite value: ~3.4e38.

The model weights typically range from -1.0 to 1.0 after initialization.
Training deltas are typically in the range -0.01 to 0.01.
Accumulated weights after many blocks may grow to -10.0 to 10.0.

All values are well within float32 range.

## Model Serving Considerations

### Inference Latency

Per-token inference cost at various model sizes:

| d_model | n_layers | n_slots | Time/Token (CPU) |
|---------|----------|---------|-------------------|
| 512 | 8 | 1,024 | ~2 ms |
| 768 | 16 | 10,024 | ~8 ms |
| 1,024 | 24 | 41,024 | ~25 ms |
| 1,024 | 24 | 401,024 | ~50 ms |

The slot score computation dominates at high slot counts.
However, since only top_k=2 slots are used, the value retrieval
and output projection remain constant.

### Batch Processing

For non-consensus inference (e.g., user applications), batch
processing can improve throughput:

- Batch size 1: ~2 ms/token (genesis)
- Batch size 8: ~1 ms/token (amortized)
- Batch size 32: ~0.5 ms/token (amortized)

Consensus evaluation uses batch size 1 for determinism.

### Model Portability

The model can be exported in standard formats:

1. **Native**: FlowCoin's internal format (ggml context dump).
2. **GGUF**: Compatible with llama.cpp and other ggml-based tools.
3. **Safetensors**: Compatible with Hugging Face ecosystem.
4. **NumPy**: Raw float32 arrays for research use.

Export is a one-way operation: the consensus model is always
maintained in the native format.

## Future Architecture Evolution

### Version Negotiation

The block header includes a `version` field. Future architecture
changes can be introduced through soft forks:

- **New sub-block types**: Add new computation modules to each layer
  (e.g., mixture of experts).
- **Attention hybrid**: Optionally enable self-attention for evaluation
  while maintaining slot memory for O(1) inference.
- **Quantization-aware training**: Evaluate in quantized precision
  for lower node requirements.

### Architecture Transitions

A major architecture change (hard fork) would require:
1. Consensus on the new architecture specification.
2. Implementation and testing on testnet.
3. Coordinated upgrade at a specific block height.
4. Model migration: convert weights from old to new architecture.

The growth schedule provides a natural migration path: new dimensions
can encode new architecture components while maintaining backward
compatibility with existing weights.
