// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Standalone GPU miner implementation for FlowCoin.
// Trains the consensus model using ggml autodiff with a simplified
// forward graph (embedding -> RMSNorm -> SwiGLU FFN -> logits -> CE loss)
// and submits blocks when the training hash meets the difficulty target.

#include "mining/gpu_miner.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/block.h"
#include "version.h"

#include "ggml/ggml.h"
#include "ggml/ggml-cpu.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// POSIX networking for HTTP RPC client
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

// Filesystem
#include <dirent.h>
#include <sys/stat.h>

namespace flow {

// ============================================================================
// Construction / destruction
// ============================================================================

GPUMiner::GPUMiner(const MinerConfig& config)
    : config_(config) {}

GPUMiner::~GPUMiner() {
    stop();
}

void GPUMiner::stop() {
    running_ = false;
}

MiningStats GPUMiner::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

// ============================================================================
// Initialization
// ============================================================================

bool GPUMiner::init() {
    // Read flowcoin.conf for RPC user/password if not set on CLI
    read_config_file();

    // Load training data from datadir/training/
    if (!load_training_data()) {
        fprintf(stderr, "  No training data found in %s/training/\n",
                config_.datadir.c_str());
        fprintf(stderr, "  Place .txt or .bin files there and restart.\n");
        return false;
    }

    printf("  Training data: %zu bytes (%d files)\n",
           dataset_.size(), file_count_);
    printf("  Dataset hash:  %s\n",
           dataset_hash_.to_hex().substr(0, 16).c_str());

    // Test RPC connection
    std::string result = rpc_call("getblockcount");
    if (result.empty()) {
        fprintf(stderr, "  Cannot connect to flowcoind at 127.0.0.1:%d\n",
                config_.rpc_port);
        fprintf(stderr, "  Make sure flowcoind is running.\n");
        return false;
    }
    printf("  Node: 127.0.0.1:%d (height %s)\n",
           config_.rpc_port, result.c_str());

    // Report backend
#if defined(GGML_USE_CUDA)
    printf("  Backend: CUDA\n");
#elif defined(GGML_USE_VULKAN)
    printf("  Backend: Vulkan\n");
#elif defined(GGML_USE_METAL)
    printf("  Backend: Metal\n");
#else
    if (config_.force_cpu) {
        printf("  Backend: CPU (forced)\n");
    } else {
        printf("  Backend: CPU (build with GGML_USE_CUDA for GPU)\n");
    }
#endif

    printf("\n");
    return true;
}

// ============================================================================
// Training data loading
// ============================================================================

bool GPUMiner::load_training_data() {
    std::string training_dir = config_.datadir + "/training";

    // Create directory if it does not exist
    mkdir(training_dir.c_str(), 0755);

    DIR* dir = opendir(training_dir.c_str());
    if (!dir) return false;

    dataset_.clear();
    file_count_ = 0;

    // Collect filenames and sort for deterministic ordering
    std::vector<std::string> filenames;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        std::string path = training_dir + "/" + name;
        struct stat st;
        if (stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            filenames.push_back(path);
        }
    }
    closedir(dir);

    std::sort(filenames.begin(), filenames.end());

    for (const auto& path : filenames) {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) continue;

        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);

        if (size <= 0) { fclose(f); continue; }

        size_t old_size = dataset_.size();
        dataset_.resize(old_size + static_cast<size_t>(size));
        size_t nread = fread(dataset_.data() + old_size, 1,
                             static_cast<size_t>(size), f);
        if (nread < static_cast<size_t>(size)) {
            dataset_.resize(old_size + nread);
        }
        fclose(f);
        file_count_++;
    }

    if (dataset_.empty()) return false;

    // Compute dataset hash
    dataset_hash_ = keccak256(dataset_.data(), dataset_.size());

    printf("  Loaded %d files from %s\n", file_count_, training_dir.c_str());
    return true;
}

// ============================================================================
// Config file parsing
// ============================================================================

void GPUMiner::read_config_file() {
    std::string conf_path = config_.datadir + "/flowcoin.conf";
    FILE* f = fopen(conf_path.c_str(), "r");
    if (!f) return;

    char line[512];
    while (fgets(line, static_cast<int>(sizeof(line)), f)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        // Parse key=value
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        std::string key = line;
        std::string value = eq + 1;

        // Trim whitespace and newlines
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t'))
            key.pop_back();
        while (!value.empty() && (value.back() == '\n' || value.back() == '\r'
               || value.back() == ' ' || value.back() == '\t'))
            value.pop_back();

        if (key == "rpcuser" && config_.rpc_user.empty())
            config_.rpc_user = value;
        if (key == "rpcpassword" && config_.rpc_password.empty())
            config_.rpc_password = value;
        if (key == "rpcport" && config_.rpc_port == 9334) {
            try { config_.rpc_port = std::stoi(value); }
            catch (...) {}
        }
    }
    fclose(f);
}

// ============================================================================
// Batch extraction
// ============================================================================

void GPUMiner::get_batch(std::vector<uint8_t>& input,
                         std::vector<uint8_t>& target) {
    int len = config_.seq_len + 1; // input + 1 target token
    if (dataset_.size() < static_cast<size_t>(len)) {
        // Dataset too small -- fill with zeros
        input.assign(static_cast<size_t>(config_.seq_len), 0);
        target.assign(static_cast<size_t>(config_.seq_len), 0);
        return;
    }

    if (data_pos_ + static_cast<size_t>(len) > dataset_.size())
        data_pos_ = 0;

    input.assign(dataset_.begin() + static_cast<ptrdiff_t>(data_pos_),
                 dataset_.begin() + static_cast<ptrdiff_t>(data_pos_)
                     + config_.seq_len);
    target.assign(dataset_.begin() + static_cast<ptrdiff_t>(data_pos_) + 1,
                  dataset_.begin() + static_cast<ptrdiff_t>(data_pos_)
                      + config_.seq_len + 1);
    data_pos_ += static_cast<size_t>(config_.seq_len);
}

// ============================================================================
// Training step (ggml autodiff — simplified forward graph)
//
// Builds a compute graph using only ops with backward implementations:
//   embedding lookup -> [RMSNorm -> SwiGLU FFN + residual] x N_layers
//   -> final RMSNorm -> logits (tied embedding) -> cross_entropy_loss
//
// This skips Conv, MinGRU, and SlotMemory sub-layers for now, but trains
// correctly with real backprop and the loss actually decreases.
// ============================================================================

float GPUMiner::training_step(ConsensusModel& model) {
    // Get batch (single sequence for now)
    std::vector<uint8_t> input, target;
    get_batch(input, target);

    const int T = config_.seq_len;
    const int64_t d = static_cast<int64_t>(model.dims().d_model);
    const int64_t d_ff = static_cast<int64_t>(model.dims().d_ff);
    const int64_t vocab = static_cast<int64_t>(model.dims().vocab);
    const uint32_t n_layers = model.num_layers();

    // ── 1. Allocate compute context ──────────────────────────────
    // Needs space for: input/target tensors, all intermediate ops,
    // gradient tensors (roughly 2x forward), graph overhead.
    // Generous allocation to avoid running out.
    const size_t n_graph_nodes = 16384;
    size_t compute_mem = 0;
    // Forward tensors: ~(T*d + T*d_ff + T*vocab) * n_layers * sizeof(float)
    compute_mem += static_cast<size_t>(T) * (d + d_ff) * n_layers * sizeof(float) * 4;
    // Logits and loss
    compute_mem += static_cast<size_t>(T) * vocab * sizeof(float) * 2;
    // One-hot targets
    compute_mem += static_cast<size_t>(T) * vocab * sizeof(float);
    // Gradient tensors (roughly same as forward)
    compute_mem *= 3;
    // Graph overhead
    compute_mem += ggml_graph_overhead_custom(n_graph_nodes, true);
    // Tensor object overhead (generous)
    compute_mem += (n_layers * 20 + 50) * 512;
    // Minimum 256MB, cap at 2GB
    if (compute_mem < 256 * 1024 * 1024) compute_mem = 256 * 1024 * 1024;
    if (compute_mem > 2048ULL * 1024 * 1024) compute_mem = 2048ULL * 1024 * 1024;

    struct ggml_init_params cparams = {
        /*.mem_size   =*/ compute_mem,
        /*.mem_buffer =*/ nullptr,
        /*.no_alloc   =*/ false,
    };
    struct ggml_context* ctx = ggml_init(cparams);
    if (!ctx) {
        fprintf(stderr, "  training_step: failed to allocate %zu MB compute context\n",
                compute_mem / (1024 * 1024));
        return 1e9f;
    }

    // ── 2. Create input tensors ──────────────────────────────────
    // Token indices as I32 for ggml_get_rows
    struct ggml_tensor* inp = ggml_new_tensor_1d(ctx, GGML_TYPE_I32, T);
    ggml_set_name(inp, "inp");
    ggml_set_input(inp);
    {
        int32_t* inp_data = reinterpret_cast<int32_t*>(inp->data);
        for (int t = 0; t < T; t++) {
            inp_data[t] = static_cast<int32_t>(input[t]);
        }
    }

    // One-hot targets for cross_entropy_loss: [T, vocab]
    struct ggml_tensor* targets_oh = ggml_new_tensor_2d(ctx, GGML_TYPE_F32, vocab, T);
    ggml_set_name(targets_oh, "targets");
    ggml_set_input(targets_oh);
    {
        float* oh = reinterpret_cast<float*>(targets_oh->data);
        std::memset(oh, 0, static_cast<size_t>(T) * vocab * sizeof(float));
        for (int t = 0; t < T; t++) {
            oh[t * vocab + static_cast<int32_t>(target[t])] = 1.0f;
        }
    }

    // ── 3. Mark model weights as trainable ───────────────────────
    // Only mark the weights we actually use in the simplified graph:
    // tok_emb, per-layer norm4_w + ffn_gate/up/down, final_norm_w
    struct ggml_tensor* tok_emb = model.get_tok_emb();
    struct ggml_tensor* final_norm_w = model.get_final_norm_w();

    ggml_set_param(tok_emb);
    ggml_set_param(final_norm_w);

    for (uint32_t l = 0; l < n_layers; l++) {
        auto& layer = model.get_layer(l);
        ggml_set_param(layer.norm4_w);
        ggml_set_param(layer.ffn_gate_w);
        ggml_set_param(layer.ffn_up_w);
        ggml_set_param(layer.ffn_down_w);
    }

    // ── 4. Build forward graph ───────────────────────────────────
    // x = embedding[tokens]  ->  shape [T, d]
    // tok_emb is [d, vocab] in ggml (ne[0]=d, ne[1]=vocab)
    // ggml_get_rows(emb, indices) picks rows from ne[1] dim: result is [d, T]
    // which in ggml means T rows of d elements each — exactly [T, d]
    struct ggml_tensor* x = ggml_get_rows(ctx, tok_emb, inp); // [d, T]

    // Per-layer: simplified to RMSNorm -> SwiGLU FFN + residual
    for (uint32_t l = 0; l < n_layers; l++) {
        auto& layer = model.get_layer(l);

        // RMSNorm (use norm4_w — the FFN norm weight)
        // ggml_rms_norm: normalize along ne[0] (d dimension)
        struct ggml_tensor* normed = ggml_rms_norm(ctx, x, 1e-6f);
        normed = ggml_mul(ctx, normed, layer.norm4_w); // broadcast mul [d] over [d, T]

        // SwiGLU FFN using split version (has backward support)
        // gate = normed @ ffn_gate_w^T  ->  [d_ff, T]
        // up   = normed @ ffn_up_w^T    ->  [d_ff, T]
        // ffn_gate_w is [d, d_ff], ggml_mul_mat does A @ B^T when A=[d,d_ff], B=[d,T]
        // result is [d_ff, T]
        struct ggml_tensor* gate = ggml_mul_mat(ctx, layer.ffn_gate_w, normed);
        struct ggml_tensor* up   = ggml_mul_mat(ctx, layer.ffn_up_w, normed);

        // SwiGLU: silu(gate) * up  (using split version for backward support)
        struct ggml_tensor* swiglu_out = ggml_swiglu_split(ctx, gate, up);
        // swiglu_out is [d_ff, T]

        // Down projection: swiglu_out @ ffn_down_w^T  ->  [d, T]
        // ffn_down_w is [d_ff, d], mul_mat does [d_ff, d] @ [d_ff, T]^T ... no.
        // ggml_mul_mat(A, B) = A @ B^T where A=[ne0_a, ne1_a] B=[ne0_b, ne1_b]
        // We want [d, T]. A=ffn_down_w=[d_ff, d], B=swiglu_out=[d_ff, T]
        // A @ B^T = [d_ff, d] @ [d_ff, T]^T = [d_ff, d] @ [T, d_ff] -> invalid
        // Actually ggml_mul_mat result shape: [ne1_a, ne1_b] when ne0_a == ne0_b
        // So A=[d_ff, d], B=[d_ff, T] -> ne0_a=d_ff==ne0_b=d_ff -> result is [d, T]. Correct!
        struct ggml_tensor* ffn_out = ggml_mul_mat(ctx, layer.ffn_down_w, swiglu_out);

        // Residual connection
        x = ggml_add(ctx, x, ffn_out);
    }

    // Final RMSNorm
    struct ggml_tensor* normed_final = ggml_rms_norm(ctx, x, 1e-6f);
    normed_final = ggml_mul(ctx, normed_final, final_norm_w);

    // Logits via tied embedding weights
    // tok_emb=[d, vocab], normed_final=[d, T]
    // We want logits=[vocab, T] so each of T positions has vocab-dim logits
    // ggml_mul_mat(tok_emb, normed_final): ne0_a=d==ne0_b=d, result=[vocab, T]. Correct!
    struct ggml_tensor* logits = ggml_mul_mat(ctx, tok_emb, normed_final);
    ggml_set_name(logits, "logits");

    // ── 5. Cross-entropy loss ────────────────────────────────────
    // ggml_cross_entropy_loss(logits, targets) expects both [vocab, T]
    // targets_oh is [vocab, T] — matches logits shape
    struct ggml_tensor* loss = ggml_cross_entropy_loss(ctx, logits, targets_oh);
    ggml_set_name(loss, "loss");
    ggml_set_loss(loss);

    // ── 6. Build compute graph (forward + backward) ──────────────
    struct ggml_cgraph* gf = ggml_new_graph_custom(ctx, n_graph_nodes, /*grads=*/true);
    ggml_build_forward_expand(gf, loss);
    ggml_build_backward_expand(ctx, gf, /*grad_accs=*/nullptr);

    // ── 7. Reset gradients and compute ───────────────────────────
    ggml_graph_reset(gf);

    struct ggml_cplan plan = ggml_graph_plan(gf, /*n_threads=*/1, /*threadpool=*/nullptr);
    std::vector<uint8_t> work_buf;
    if (plan.work_size > 0) {
        work_buf.resize(plan.work_size);
        plan.work_data = work_buf.data();
    }
    ggml_graph_compute(gf, &plan);

    // ── 8. Extract loss value ────────────────────────────────────
    float loss_val = ggml_get_f32_1d(loss, 0);

    // ── 9. Update weights: w -= lr * grad ────────────────────────
    float lr = config_.learning_rate;

    auto update_weight = [&](struct ggml_tensor* w) {
        if (!w) return;
        struct ggml_tensor* grad = ggml_graph_get_grad_acc(gf, w);
        if (!grad) return;
        float* wd = ggml_get_data_f32(w);
        const float* gd = ggml_get_data_f32(grad);
        int64_t ne = ggml_nelements(w);
        for (int64_t i = 0; i < ne; i++) {
            wd[i] -= lr * gd[i];
        }
    };

    update_weight(tok_emb);
    update_weight(final_norm_w);
    for (uint32_t l = 0; l < n_layers; l++) {
        auto& layer = model.get_layer(l);
        update_weight(layer.norm4_w);
        update_weight(layer.ffn_gate_w);
        update_weight(layer.ffn_up_w);
        update_weight(layer.ffn_down_w);
    }

    // ── 10. Clear param flags so they don't interfere with
    //        ConsensusModel's own forward_eval later ──────────────
    tok_emb->flags &= ~(GGML_TENSOR_FLAG_PARAM | GGML_TENSOR_FLAG_LOSS);
    final_norm_w->flags &= ~(GGML_TENSOR_FLAG_PARAM | GGML_TENSOR_FLAG_LOSS);
    for (uint32_t l = 0; l < n_layers; l++) {
        auto& layer = model.get_layer(l);
        layer.norm4_w->flags &= ~GGML_TENSOR_FLAG_PARAM;
        layer.ffn_gate_w->flags &= ~GGML_TENSOR_FLAG_PARAM;
        layer.ffn_up_w->flags &= ~GGML_TENSOR_FLAG_PARAM;
        layer.ffn_down_w->flags &= ~GGML_TENSOR_FLAG_PARAM;
    }

    // ── 11. Free compute context ─────────────────────────────────
    ggml_free(ctx);

    return loss_val;
}

// ============================================================================
// Hash computation and target checking
// ============================================================================

uint256 GPUMiner::compute_training_hash(const std::vector<float>& delta) {
    // delta_hash = keccak256(delta_bytes)
    uint256 delta_hash = keccak256(
        reinterpret_cast<const uint8_t*>(delta.data()),
        delta.size() * sizeof(float));

    // training_hash = keccak256(delta_hash || dataset_hash)
    CKeccak256 hasher;
    hasher.update(delta_hash.data(), delta_hash.size());
    hasher.update(dataset_hash_.data(), dataset_hash_.size());
    return hasher.finalize();
}

bool GPUMiner::check_target(const uint256& hash, const uint256& target) {
    return hash_meets_target(hash, target);
}

// ============================================================================
// Block submission
// ============================================================================

bool GPUMiner::submit_block(const BlockTemplate& tmpl,
                            const ConsensusModel& model,
                            const std::vector<float>& consensus_weights,
                            float val_loss) {
    // Generate a fresh keypair for this block
    KeyPair kp = generate_keypair();

    // Compute delta
    std::vector<float> trained = model.get_weights();
    size_t n = std::min(trained.size(), consensus_weights.size());
    std::vector<float> delta(n);
    uint32_t sparse_count = 0;
    for (size_t i = 0; i < n; i++) {
        delta[i] = trained[i] - consensus_weights[i];
        if (std::fabs(delta[i]) < config_.sparse_threshold) {
            delta[i] = 0.0f;
        } else {
            sparse_count++;
        }
    }

    // Sparse encoding: [count:u32][idx:u32, val:f32] * count
    std::vector<uint8_t> delta_payload;
    delta_payload.resize(4 + sparse_count * 8);
    std::memcpy(delta_payload.data(), &sparse_count, 4);
    size_t offset = 4;
    for (uint32_t i = 0; i < static_cast<uint32_t>(n); i++) {
        if (delta[i] != 0.0f) {
            std::memcpy(delta_payload.data() + offset, &i, 4);
            std::memcpy(delta_payload.data() + offset + 4, &delta[i], 4);
            offset += 8;
        }
    }

    // Hash the delta for training hash
    uint256 delta_hash = keccak256(
        reinterpret_cast<const uint8_t*>(delta.data()),
        delta.size() * sizeof(float));

    // Build block header
    CBlockHeader hdr;
    hdr.height = tmpl.height;
    hdr.prev_hash = tmpl.prev_hash;
    hdr.nbits = tmpl.nbits;
    hdr.val_loss = val_loss;
    hdr.prev_val_loss = tmpl.prev_val_loss;
    hdr.version = 1;
    hdr.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Architecture dimensions
    hdr.d_model = tmpl.dims.d_model;
    hdr.n_layers = tmpl.dims.n_layers;
    hdr.d_ff = tmpl.dims.d_ff;
    hdr.n_heads = tmpl.dims.n_heads;
    hdr.gru_dim = tmpl.dims.gru_dim;
    hdr.n_slots = tmpl.dims.n_slots;

    // Delta metadata
    hdr.delta_offset = 0;
    hdr.delta_length = static_cast<uint32_t>(delta_payload.size());
    hdr.sparse_count = sparse_count;
    hdr.sparse_threshold = config_.sparse_threshold;
    hdr.nonce = 0;

    // Training hash
    CKeccak256 th;
    th.update(delta_hash.data(), delta_hash.size());
    th.update(dataset_hash_.data(), dataset_hash_.size());
    hdr.training_hash = th.finalize();
    hdr.dataset_hash = dataset_hash_;

    // Miner identity
    std::copy(kp.pubkey.begin(), kp.pubkey.end(), hdr.miner_pubkey.begin());

    // Sign the unsigned header data
    auto unsigned_data = hdr.get_unsigned_data();
    auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                            kp.privkey.data(), kp.pubkey.data());
    std::copy(sig.begin(), sig.end(), hdr.miner_sig.begin());

    // Build coinbase transaction
    CBlock block(hdr);
    block.vtx.push_back(
        CBlock::make_coinbase(tmpl.height, tmpl.reward, kp.pubkey, ""));

    // Compute merkle root
    block.merkle_root = block.compute_merkle_root();

    // Re-sign with updated merkle root
    auto unsigned_data2 = block.get_unsigned_data();
    auto sig2 = ed25519_sign(unsigned_data2.data(), unsigned_data2.size(),
                             kp.privkey.data(), kp.pubkey.data());
    std::copy(sig2.begin(), sig2.end(), block.miner_sig.begin());

    // Attach delta payload
    block.delta_payload = delta_payload;

    // Serialize to hex and submit
    auto serialized = block.serialize();
    std::string hex;
    hex.reserve(serialized.size() * 2);
    static const char hx[] = "0123456789abcdef";
    for (uint8_t b : serialized) {
        hex.push_back(hx[b >> 4]);
        hex.push_back(hx[b & 0xF]);
    }

    std::string resp = rpc_call("submitblock", "[\"" + hex + "\"]");
    bool ok = !resp.empty() && (resp == "null" || resp.find("error") == std::string::npos);
    if (ok) {
        printf("  Block submitted successfully at height %lu\n",
               static_cast<unsigned long>(tmpl.height));
    } else {
        printf("  Block submission FAILED at height %lu\n",
               static_cast<unsigned long>(tmpl.height));
    }
    return ok;
}

// ============================================================================
// RPC communication
// ============================================================================

std::string GPUMiner::rpc_call(const std::string& method,
                               const std::string& params) {
    // Build JSON-RPC request
    std::string body = "{\"jsonrpc\":\"2.0\",\"method\":\"" + method +
                       "\",\"params\":" + params + ",\"id\":1}";

    // TCP connect to 127.0.0.1:rpc_port
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(config_.rpc_port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    // Set timeouts
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr),
                sizeof(addr)) < 0) {
        close(sock);
        return "";
    }

    // Build HTTP request with Basic auth
    std::string auth = config_.rpc_user + ":" + config_.rpc_password;
    std::string auth_b64 = base64_encode(auth);

    std::string http = "POST / HTTP/1.1\r\n"
                       "Host: 127.0.0.1\r\n"
                       "Authorization: Basic " + auth_b64 + "\r\n"
                       "Content-Type: application/json\r\n"
                       "Content-Length: " + std::to_string(body.size()) + "\r\n"
                       "Connection: close\r\n\r\n" + body;

    ssize_t sent = send(sock, http.c_str(), http.size(), 0);
    if (sent < 0 || static_cast<size_t>(sent) != http.size()) {
        close(sock);
        return "";
    }

    // Read response
    std::string response;
    char buf[4096];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        response.append(buf, static_cast<size_t>(n));
    }
    close(sock);

    // Parse HTTP response -- find JSON body after \r\n\r\n
    auto body_start = response.find("\r\n\r\n");
    if (body_start == std::string::npos) return "";
    std::string json_body = response.substr(body_start + 4);

    // Extract "result" from JSON
    std::string result = extract_json_value(json_body, "result");
    return result;
}

// ============================================================================
// JSON parsing helpers
// ============================================================================

std::string GPUMiner::extract_json_value(const std::string& json,
                                          const std::string& key) const {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return "";
    pos++;

    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
                                  json[pos] == '\n' || json[pos] == '\r'))
        pos++;

    if (pos >= json.size()) return "";

    // Handle different value types
    if (json[pos] == '{') {
        int depth = 1;
        size_t start = pos;
        pos++;
        while (pos < json.size() && depth > 0) {
            if (json[pos] == '{') depth++;
            else if (json[pos] == '}') depth--;
            pos++;
        }
        return json.substr(start, pos - start);
    }
    if (json[pos] == '[') {
        int depth = 1;
        size_t start = pos;
        pos++;
        while (pos < json.size() && depth > 0) {
            if (json[pos] == '[') depth++;
            else if (json[pos] == ']') depth--;
            pos++;
        }
        return json.substr(start, pos - start);
    }
    if (json[pos] == '"') {
        pos++; // skip opening quote
        size_t start = pos;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\') pos++; // skip escaped char
            pos++;
        }
        return json.substr(start, pos - start);
    }
    // Number, bool, or null
    size_t start = pos;
    while (pos < json.size() && json[pos] != ',' &&
           json[pos] != '}' && json[pos] != ']' &&
           json[pos] != '\n' && json[pos] != '\r')
        pos++;
    std::string val = json.substr(start, pos - start);
    // Trim trailing whitespace
    while (!val.empty() && (val.back() == ' ' || val.back() == '\t'))
        val.pop_back();
    return val;
}

std::string GPUMiner::extract_json_string(const std::string& json,
                                           const std::string& key) const {
    return extract_json_value(json, key);
}

int64_t GPUMiner::extract_json_int(const std::string& json,
                                    const std::string& key) const {
    std::string val = extract_json_value(json, key);
    if (val.empty() || val == "null") return 0;
    try { return std::stoll(val); }
    catch (...) { return 0; }
}

double GPUMiner::extract_json_float(const std::string& json,
                                     const std::string& key) const {
    std::string val = extract_json_value(json, key);
    if (val.empty() || val == "null") return 0.0;
    try { return std::stod(val); }
    catch (...) { return 0.0; }
}

uint256 GPUMiner::parse_uint256(const std::string& hex) const {
    uint256 result;
    result.set_null();
    if (hex.size() != 64) return result;

    for (size_t i = 0; i < 32; i++) {
        std::string byte_str = hex.substr(i * 2, 2);
        try {
            result[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        } catch (...) {
            result.set_null();
            return result;
        }
    }
    return result;
}

// ============================================================================
// Base64 encoder for HTTP Basic auth
// ============================================================================

std::string GPUMiner::base64_encode(const std::string& input) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i < input.size()) {
        uint32_t a = static_cast<uint8_t>(input[i++]);
        uint32_t b = (i < input.size()) ? static_cast<uint8_t>(input[i++]) : 0;
        uint32_t c = (i < input.size()) ? static_cast<uint8_t>(input[i++]) : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        size_t consumed = i;
        // Determine how many input bytes were actually available
        size_t start_pos = consumed - 3;
        if (consumed > input.size()) consumed = input.size();
        size_t remaining = consumed - start_pos;

        out.push_back(table[(triple >> 18) & 0x3F]);
        out.push_back(table[(triple >> 12) & 0x3F]);
        out.push_back(remaining > 1 ? table[(triple >> 6) & 0x3F] : '=');
        out.push_back(remaining > 2 ? table[triple & 0x3F] : '=');
    }
    return out;
}

// ============================================================================
// Status printing
// ============================================================================

void GPUMiner::print_status(uint64_t height, uint64_t step, float loss,
                            float best_loss, double steps_per_sec) {
    uint64_t checks;
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        checks = stats_.hash_checks;
    }
    printf("\r  block %lu | step %6lu | loss %.4f | best %.4f | %.0f st/s | checks %lu",
           static_cast<unsigned long>(height),
           static_cast<unsigned long>(step),
           loss, best_loss, steps_per_sec,
           static_cast<unsigned long>(checks));
    fflush(stdout);
}

// ============================================================================
// Main mining loop
// ============================================================================

void GPUMiner::run() {
    running_ = true;

    while (running_) {
        // 1. Get block template
        std::string tmpl_json = rpc_call("getblocktemplate");
        if (tmpl_json.empty() || tmpl_json == "null") {
            printf("  Waiting for node...\n");
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        // Parse block template
        BlockTemplate tmpl;
        tmpl.height = static_cast<uint64_t>(
            extract_json_int(tmpl_json, "height"));
        tmpl.prev_hash = parse_uint256(
            extract_json_string(tmpl_json, "previousblockhash"));
        tmpl.nbits = static_cast<uint32_t>(
            extract_json_int(tmpl_json, "bits"));
        tmpl.prev_val_loss = static_cast<float>(
            extract_json_float(tmpl_json, "prev_val_loss"));
        tmpl.reward = extract_json_int(tmpl_json, "coinbasevalue");
        tmpl.target = parse_uint256(
            extract_json_string(tmpl_json, "target"));

        // Compute dimensions from height using growth schedule
        tmpl.dims = consensus::compute_growth(tmpl.height);

        printf("  Mining block %lu (d=%u L=%u slots=%u)\n",
               static_cast<unsigned long>(tmpl.height),
               tmpl.dims.d_model, tmpl.dims.n_layers, tmpl.dims.n_slots);

        // 2. Init model
        ConsensusModel model;
        if (!model.init(tmpl.dims, consensus::GENESIS_SEED)) {
            fprintf(stderr, "  Error: failed to initialize model\n");
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        printf("  Model: %zu parameters (%.1f MB)\n",
               model.param_count(),
               model.param_count() * 4.0 / 1048576.0);

        // Try to load consensus weights from node
        std::string weights_json = rpc_call("getmodelweights");
        if (!weights_json.empty() && weights_json != "null" &&
            weights_json.front() == '[') {
            // Parse float array
            std::vector<float> node_weights;
            size_t pos = 1; // skip '['
            while (pos < weights_json.size()) {
                while (pos < weights_json.size() &&
                       (weights_json[pos] == ' ' || weights_json[pos] == ',' ||
                        weights_json[pos] == '\n' || weights_json[pos] == '\r'))
                    pos++;
                if (pos >= weights_json.size() || weights_json[pos] == ']')
                    break;
                size_t end = pos;
                while (end < weights_json.size() && weights_json[end] != ',' &&
                       weights_json[end] != ']' && weights_json[end] != ' ')
                    end++;
                try {
                    node_weights.push_back(
                        std::stof(weights_json.substr(pos, end - pos)));
                } catch (...) {
                    break;
                }
                pos = end;
            }
            if (!node_weights.empty() && model.set_weights(node_weights)) {
                printf("  Loaded consensus weights from node\n");
            } else {
                printf("  Using genesis model weights\n");
            }
        } else {
            printf("  Using genesis model weights\n");
        }

        // Snapshot consensus weights for delta computation
        std::vector<float> consensus_weights = model.get_weights();

        // 3. Training loop
        float best_loss = 1e9f;
        uint64_t step = 0;
        auto cycle_start = std::chrono::steady_clock::now();

        while (running_) {
            float loss = training_step(model);
            step++;

            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.total_steps++;
                stats_.current_loss = loss;
                if (loss < best_loss) {
                    best_loss = loss;
                    stats_.best_loss = best_loss;
                }
            }

            // Print status every 10 steps
            if (step % 10 == 0) {
                auto now = std::chrono::steady_clock::now();
                double elapsed =
                    std::chrono::duration<double>(now - cycle_start).count();
                double sps = (elapsed > 0) ? step / elapsed : 0;
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.steps_per_second = static_cast<float>(sps);
                }
                print_status(tmpl.height, step, loss, best_loss, sps);
            }

            // Hash check every N steps
            if (step % static_cast<uint64_t>(config_.steps_per_check) == 0) {
                auto current_weights = model.get_weights();

                // Delta = current - consensus
                std::vector<float> delta(current_weights.size());
                for (size_t i = 0; i < delta.size(); i++) {
                    delta[i] = current_weights[i] -
                        (i < consensus_weights.size() ? consensus_weights[i] : 0.0f);
                }

                // Apply sparse threshold
                for (size_t i = 0; i < delta.size(); i++) {
                    if (std::fabs(delta[i]) < config_.sparse_threshold)
                        delta[i] = 0.0f;
                }

                uint256 training_hash = compute_training_hash(delta);

                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.hash_checks++;
                }

                if (check_target(training_hash, tmpl.target)) {
                    printf("\n\n  *** BLOCK FOUND at step %lu! ***\n",
                           static_cast<unsigned long>(step));
                    printf("  Hash: %s\n",
                           training_hash.to_hex().substr(0, 16).c_str());

                    // Compute validation loss on consensus eval data
                    auto val_data = generate_validation_data(
                        VALIDATION_SEED, consensus::EVAL_TOKENS);
                    float val_loss = model.forward_eval(val_data);
                    printf("  Loss: %.4f\n\n", val_loss);

                    if (submit_block(tmpl, model, consensus_weights,
                                     val_loss)) {
                        std::lock_guard<std::mutex> lock(stats_mutex_);
                        stats_.blocks_found++;
                    }
                    break; // restart cycle for next block
                }
            }

            // Check for new block from network every 500 steps
            if (step % 500 == 0) {
                std::string count_str = rpc_call("getblockcount");
                if (!count_str.empty() && count_str != "null") {
                    try {
                        uint64_t current = std::stoull(count_str);
                        if (current >= tmpl.height) {
                            printf("\n  New block from network, restarting...\n");
                            break;
                        }
                    } catch (...) {}
                }
            }
        }
    }

    printf("\nMining loop stopped.\n");
}

} // namespace flow
