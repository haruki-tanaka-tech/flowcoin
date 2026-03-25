// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Benchmarks for the ConsensusModel: initialization, forward evaluation,
// weight serialization, delta application, model expansion, and
// validation data generation.

#include "bench.h"
#include "consensus/consensus_model.h"
#include "consensus/params.h"

#include <cstring>
#include <vector>

namespace flow::bench {

// Shared small-model dimensions for fast benchmarking
static consensus::ModelDimensions small_dims() {
    return consensus::ModelDimensions{
        128,   // d_model
        2,     // n_layers
        2,     // n_heads
        64,    // d_head
        256,   // d_ff
        64,    // n_slots
        2,     // top_k
        128,   // gru_dim
        4,     // conv_kernel
        256,   // vocab
        64,    // seq_len (short for benchmarking)
    };
}

// ===========================================================================
// Model initialization
// ===========================================================================

BENCH(Model_Init_Small) {
    auto dims = small_dims();
    for (int i = 0; i < _iterations; i++) {
        ConsensusModel model;
        bool ok = model.init(dims, 42 + static_cast<uint32_t>(i));
        if (!ok) break;
    }
}

BENCH(Model_Init_Genesis) {
    // Full genesis dimensions (slower)
    consensus::ModelDimensions dims{
        consensus::GENESIS_D_MODEL,
        consensus::GENESIS_N_LAYERS,
        consensus::GENESIS_N_HEADS,
        consensus::GENESIS_D_HEAD,
        consensus::GENESIS_D_FF,
        consensus::GENESIS_N_SLOTS,
        consensus::GENESIS_TOP_K,
        consensus::GENESIS_GRU_DIM,
        consensus::GENESIS_CONV_KERNEL,
        consensus::GENESIS_VOCAB,
        consensus::GENESIS_SEQ_LEN,
    };
    for (int i = 0; i < _iterations; i++) {
        ConsensusModel model;
        bool ok = model.init(dims, 42);
        if (!ok) break;
    }
}

// ===========================================================================
// Forward evaluation
// ===========================================================================

BENCH(Model_ForwardEval_Small) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    // Generate validation data
    auto val_data = generate_validation_data("bench_eval", dims.seq_len);

    for (int i = 0; i < _iterations; i++) {
        float loss = model.forward_eval(val_data);
        // Prevent optimization
        if (loss < -1e30f) break;
    }
}

// ===========================================================================
// Weight management
// ===========================================================================

BENCH(Model_GetWeights) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    for (int i = 0; i < _iterations; i++) {
        auto weights = model.get_weights();
        // Prevent optimization
        if (weights.empty()) break;
    }
}

BENCH(Model_SetWeights) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);
    auto weights = model.get_weights();

    for (int i = 0; i < _iterations; i++) {
        weights[0] = static_cast<float>(i) * 0.001f;
        bool ok = model.set_weights(weights);
        if (!ok) break;
    }
}

BENCH(Model_GetWeightsHash) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    for (int i = 0; i < _iterations; i++) {
        uint256 hash = model.get_weights_hash();
        (void)hash;
    }
}

// ===========================================================================
// Delta operations
// ===========================================================================

BENCH(Model_ApplyDelta_Small) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    // Create a small sparse delta (10% non-zero)
    size_t n_params = model.param_count();
    std::vector<float> delta(n_params, 0.0f);
    for (size_t j = 0; j < n_params; j += 10) {
        delta[j] = 0.001f * static_cast<float>(j % 100);
    }

    for (int i = 0; i < _iterations; i++) {
        bool ok = model.apply_delta(delta);
        if (!ok) break;
    }
}

BENCH(Model_ApplyDelta_Dense) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    size_t n_params = model.param_count();
    std::vector<float> delta(n_params);
    for (size_t j = 0; j < n_params; j++) {
        delta[j] = 0.0001f * static_cast<float>(j % 1000);
    }

    for (int i = 0; i < _iterations; i++) {
        bool ok = model.apply_delta(delta);
        if (!ok) break;
    }
}

// ===========================================================================
// Model expansion
// ===========================================================================

BENCH(Model_Expand) {
    auto dims = small_dims();
    // Expand from 128 to 192 d_model
    consensus::ModelDimensions bigger = dims;
    bigger.d_model = 192;
    bigger.d_ff = 384;
    bigger.gru_dim = 192;
    bigger.n_layers = 3;

    for (int i = 0; i < _iterations; i++) {
        ConsensusModel model;
        model.init(dims, 42);
        bool ok = model.expand_to(bigger);
        if (!ok) break;
    }
}

// ===========================================================================
// Model clone and diff
// ===========================================================================

BENCH(Model_Clone) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    for (int i = 0; i < _iterations; i++) {
        ConsensusModel cloned = model.clone();
        (void)cloned;
    }
}

BENCH(Model_Diff) {
    auto dims = small_dims();
    ConsensusModel a, b;
    a.init(dims, 42);
    b.init(dims, 43);

    for (int i = 0; i < _iterations; i++) {
        auto delta = a.diff(b);
        if (delta.empty()) break;
    }
}

// ===========================================================================
// Validation data generation
// ===========================================================================

BENCH(ValidationData_4096Tokens) {
    for (int i = 0; i < _iterations; i++) {
        auto data = generate_validation_data("bench_seed_" + std::to_string(i), 4096);
        if (data.empty()) break;
    }
}

BENCH(ValidationData_256Tokens) {
    for (int i = 0; i < _iterations; i++) {
        auto data = generate_validation_data("bench_seed_" + std::to_string(i), 256);
        if (data.empty()) break;
    }
}

// ===========================================================================
// Quantization
// ===========================================================================

BENCH(Model_QuantizeInt8) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    for (int i = 0; i < _iterations; i++) {
        auto quantized = model.quantize_weights_int8();
        if (quantized.empty()) break;
    }
}

BENCH(Model_LayerStats) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    for (int i = 0; i < _iterations; i++) {
        auto stats = model.get_layer_stats();
        if (stats.empty()) break;
    }
}

// ===========================================================================
// Model memory usage
// ===========================================================================

BENCH(Model_MemoryUsage) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    for (int i = 0; i < _iterations; i++) {
        size_t mem = model.memory_usage();
        if (mem == 0) break;
    }
}

// ===========================================================================
// Model architecture validation
// ===========================================================================

BENCH(Model_ValidateArchitecture) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    for (int i = 0; i < _iterations; i++) {
        bool valid = model.validate_architecture();
        if (!valid) break;
    }
}

// ===========================================================================
// Model parameter count
// ===========================================================================

BENCH(Model_ParamCount) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    for (int i = 0; i < _iterations; i++) {
        size_t pc = model.param_count();
        if (pc == 0) break;
    }
}

// ===========================================================================
// Model save/load roundtrip
// ===========================================================================

BENCH(Model_SaveLoad) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);
    std::string path = "/tmp/flowbench_model_XXXXXX";

    for (int i = 0; i < _iterations; i++) {
        model.save_to_file(path);
        ConsensusModel loaded;
        loaded.load_from_file(path);
    }
    std::remove(path.c_str());
}

// ===========================================================================
// Load quantized weights
// ===========================================================================

BENCH(Model_LoadQuantizedInt8) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);
    auto quantized = model.quantize_weights_int8();

    for (int i = 0; i < _iterations; i++) {
        ConsensusModel loaded;
        loaded.init(dims, 0);
        bool ok = loaded.load_quantized_int8(quantized);
        if (!ok) break;
    }
}

// ===========================================================================
// Multiple forward evals (simulating block validation)
// ===========================================================================

BENCH(Model_ForwardEval_Multiple) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    // Generate multiple validation datasets
    std::vector<std::vector<uint8_t>> datasets;
    for (int j = 0; j < 5; j++) {
        datasets.push_back(
            generate_validation_data("bench_multi_" + std::to_string(j), dims.seq_len));
    }

    for (int i = 0; i < _iterations; i++) {
        float total_loss = 0.0f;
        for (const auto& data : datasets) {
            total_loss += model.forward_eval(data);
        }
        if (total_loss < -1e30f) break;
    }
}

// ===========================================================================
// Delta with apply and hash verification
// ===========================================================================

BENCH(Model_DeltaApplyAndHash) {
    auto dims = small_dims();
    ConsensusModel model;
    model.init(dims, 42);

    size_t n_params = model.param_count();
    std::vector<float> delta(n_params, 0.0f);
    for (size_t j = 0; j < n_params; j += 5) {
        delta[j] = 0.0005f * static_cast<float>(j % 200 - 100);
    }

    for (int i = 0; i < _iterations; i++) {
        model.apply_delta(delta);
        uint256 hash = model.get_weights_hash();
        (void)hash;
    }
}

} // namespace flow::bench
