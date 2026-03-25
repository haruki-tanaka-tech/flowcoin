cmake_minimum_required(VERSION 3.20)
project(flowcoin VERSION 1.0.0 LANGUAGES C CXX)

# =============================================================================
# Language standards
# =============================================================================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# =============================================================================
# Compiler flags
# =============================================================================
# NOTE: -ffast-math is intentionally omitted — it breaks IEEE 754 determinism
# which is required for consensus evaluation across heterogeneous hardware.
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror=return-type
)

# =============================================================================
# Deterministic build options
# =============================================================================
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Reproducible builds: strip file prefix map for deterministic debug info
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    add_compile_options(
        "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=."
        "-fmacro-prefix-map=${CMAKE_SOURCE_DIR}=."
    )
endif()

# Disable RPATH for reproducibility
set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_SKIP_INSTALL_RPATH TRUE)

# Use consistent archive creation
set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> qcD <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> qcD <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_C_ARCHIVE_APPEND "<CMAKE_AR> qD <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_CXX_ARCHIVE_APPEND "<CMAKE_AR> qD <TARGET> <LINK_FLAGS> <OBJECTS>")

# =============================================================================
# Vendored libraries
# =============================================================================

# --- ggml (GGML tensor library, CPU backend) ---
add_library(ggml STATIC
    src/ggml/ggml.c
    src/ggml/ggml.cpp
    src/ggml/ggml-alloc.c
    src/ggml/ggml-backend.cpp
    src/ggml/ggml-threading.cpp
    src/ggml/ggml-quants.c
    src/ggml/ggml-opt.cpp
    src/ggml/gguf.cpp
    src/ggml/ggml-cpu/ggml-cpu.c
    src/ggml/ggml-cpu/ggml-cpu.cpp
    src/ggml/ggml-cpu/ops.cpp
    src/ggml/ggml-cpu/vec.cpp
    src/ggml/ggml-cpu/unary-ops.cpp
    src/ggml/ggml-cpu/binary-ops.cpp
    src/ggml/ggml-cpu/quants.c
    src/ggml/ggml-cpu/repack.cpp
    src/ggml/ggml-cpu/traits.cpp
    src/ggml/ggml-cpu/hbm.cpp
    src/ggml/ggml-cpu/llamafile/sgemm.cpp
    src/ggml/ggml-cpu/arch/x86/quants.c
    src/ggml/ggml-cpu/arch/x86/cpu-feats.cpp
    src/ggml/ggml-cpu/arch/x86/repack.cpp
)
target_compile_definitions(ggml PUBLIC GGML_USE_CPU _GNU_SOURCE
    GGML_VERSION="0.0.0"
    GGML_COMMIT="flowcoin"
)
target_include_directories(ggml PUBLIC
    src/ggml
    src/ggml/ggml-cpu
    src/ggml/ggml-cpu/arch
)
# Suppress warnings and errors in vendored code
target_compile_options(ggml PRIVATE -w -Wno-error -Wno-all -Wno-extra)
set_target_properties(ggml PROPERTIES
    C_EXTENSIONS ON
    CXX_EXTENSIONS ON
)

# --- sqlite ---
add_library(sqlite STATIC
    src/sqlite/sqlite3.c
)
target_compile_definitions(sqlite PRIVATE
    SQLITE_THREADSAFE=1
    SQLITE_DEFAULT_WAL_SYNCHRONOUS=1
    SQLITE_OMIT_LOAD_EXTENSION
)
target_include_directories(sqlite PUBLIC src/sqlite)
target_compile_options(sqlite PRIVATE -w)

# --- ed25519 (ed25519-donna) ---
add_library(ed25519 STATIC
    src/crypto/ed25519.c
)
target_compile_definitions(ed25519 PUBLIC
    ED25519_CUSTOMHASH
    ED25519_CUSTOMRNG
)
target_include_directories(ed25519 PUBLIC src/crypto)
target_compile_options(ed25519 PRIVATE -w)

# --- xkcp (Keccak reference implementation) ---
add_library(xkcp STATIC
    src/hash/KeccakSponge.c
    src/hash/KeccakP-1600-reference.c
    src/hash/KeccakHash.c
)
target_include_directories(xkcp PUBLIC src/hash)
target_compile_options(xkcp PRIVATE -w)

# --- zstd (Zstandard compression) ---
add_library(zstd STATIC
    src/zstd/zstd.c
)
target_compile_definitions(zstd PRIVATE ZSTD_MULTITHREAD=0)
target_include_directories(zstd PUBLIC src/zstd)
target_compile_options(zstd PRIVATE -w)

# --- libuv (event loop, has its own build system) ---
set(LIBUV_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(LIBUV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LIBUV_BUILD_BENCH OFF CACHE BOOL "" FORCE)
add_subdirectory(src/libuv)

# --- json (header-only nlohmann/json) ---
add_library(json INTERFACE)
target_include_directories(json INTERFACE src/json)

# =============================================================================
# FlowCoin libraries
# =============================================================================

# --- flowcoin_compat ---
add_library(flowcoin_compat STATIC
    src/compat/cpuid.cpp
    src/compat/glibcxx_sanity.cpp
)
target_include_directories(flowcoin_compat PUBLIC src)
target_link_libraries(flowcoin_compat PUBLIC pthread)

# --- flowcoin_support ---
add_library(flowcoin_support STATIC
    src/support/lockedpool.cpp
    src/support/cleanse.cpp
)
target_include_directories(flowcoin_support PUBLIC src)
target_link_libraries(flowcoin_support PUBLIC pthread)

# --- flowcoin_util ---
add_library(flowcoin_util STATIC
    src/util/arith_uint256.cpp
    src/util/strencodings.cpp
    src/util/time.cpp
    src/util/random.cpp
    src/util/threadpool.cpp
    src/util/fs.cpp
    src/util/system.cpp
    src/util/logging.cpp
    src/util/serialize.cpp
)
target_include_directories(flowcoin_util PUBLIC src)
target_link_libraries(flowcoin_util PUBLIC xkcp pthread)

# --- flowcoin_hash ---
add_library(flowcoin_hash STATIC
    src/hash/keccak.cpp
    src/hash/merkle.cpp
    src/hash/bloom.cpp
)
target_include_directories(flowcoin_hash PUBLIC src)
target_link_libraries(flowcoin_hash PUBLIC xkcp)

# --- flowcoin_crypto ---
add_library(flowcoin_crypto STATIC
    src/crypto/keys.cpp
    src/crypto/sign.cpp
    src/crypto/bech32.cpp
    src/crypto/slip0010.cpp
    src/crypto/hmac_sha512.cpp
    src/crypto/aes256.cpp
)
target_include_directories(flowcoin_crypto PUBLIC src)
target_link_libraries(flowcoin_crypto PUBLIC ed25519 flowcoin_hash)

# --- flowcoin_common ---
add_library(flowcoin_common STATIC
    src/common/args.cpp
    src/common/system.cpp
    src/common/settings.cpp
    src/common/config_options.cpp
)
target_include_directories(flowcoin_common PUBLIC src)
target_link_libraries(flowcoin_common PUBLIC flowcoin_compat pthread)

# --- flowcoin_consensus ---
add_library(flowcoin_consensus STATIC
    src/consensus/validation.cpp
    src/consensus/difficulty.cpp
    src/consensus/reward.cpp
    src/consensus/growth.cpp
    src/consensus/merkle.cpp
    src/consensus/eval.cpp
    src/consensus/consensus_model.cpp
    src/consensus/genesis.cpp
    src/consensus/pow.cpp
)
target_include_directories(flowcoin_consensus PUBLIC src)
target_link_libraries(flowcoin_consensus PUBLIC flowcoin_hash flowcoin_util ggml zstd)

# --- flowcoin_primitives ---
add_library(flowcoin_primitives STATIC
    src/primitives/block.cpp
    src/primitives/transaction.cpp
    src/primitives/delta.cpp
    src/primitives/compact.cpp
)
target_include_directories(flowcoin_primitives PUBLIC src)
target_link_libraries(flowcoin_primitives PUBLIC flowcoin_util flowcoin_hash zstd)

# --- flowcoin_chain ---
add_library(flowcoin_chain STATIC
    src/chain/chainstate.cpp
    src/chain/blockindex.cpp
    src/chain/blockstore.cpp
    src/chain/utxo.cpp
    src/chain/txindex.cpp
    src/chain/modelstate.cpp
    src/chain/chaindb.cpp
)
target_include_directories(flowcoin_chain PUBLIC src)
target_link_libraries(flowcoin_chain PUBLIC flowcoin_consensus flowcoin_primitives sqlite)

# --- flowcoin_net ---
add_library(flowcoin_net STATIC
    src/net/net.cpp
    src/net/protocol.cpp
    src/net/peer.cpp
    src/net/messages.cpp
    src/net/addrman.cpp
    src/net/banman.cpp
    src/net/sync.cpp
    src/net/netaddress.cpp
    src/net/netbase.cpp
)
target_include_directories(flowcoin_net PUBLIC src)
target_link_libraries(flowcoin_net PUBLIC flowcoin_chain uv_a)

# --- flowcoin_wallet ---
add_library(flowcoin_wallet STATIC
    src/wallet/wallet.cpp
    src/wallet/walletdb.cpp
    src/wallet/hdchain.cpp
    src/wallet/coinselect.cpp
    src/wallet/txbuilder.cpp
    src/wallet/fees.cpp
    src/wallet/walletutil.cpp
    src/wallet/encryption.cpp
    src/wallet/keypool.cpp
    src/wallet/backup.cpp
)
target_include_directories(flowcoin_wallet PUBLIC src)
target_link_libraries(flowcoin_wallet PUBLIC flowcoin_chain flowcoin_crypto sqlite)

# --- flowcoin_rpc ---
add_library(flowcoin_rpc STATIC
    src/rpc/server.cpp
    src/rpc/blockchain.cpp
    src/rpc/mining.cpp
    src/rpc/wallet.cpp
    src/rpc/net.cpp
    src/rpc/rawtransaction.cpp
    src/rpc/training.cpp
    src/rpc/util.cpp
    src/rpc/debug.cpp
    src/rpc/register.cpp
)
target_include_directories(flowcoin_rpc PUBLIC src)
target_link_libraries(flowcoin_rpc PUBLIC
    flowcoin_chain flowcoin_wallet flowcoin_mempool flowcoin_net json uv_a
)

# --- flowcoin_mining ---
add_library(flowcoin_mining STATIC
    src/mining/blocktemplate.cpp
    src/mining/submitblock.cpp
    src/mining/miner.cpp
    src/mining/difficulty.cpp
    src/mining/stratum.cpp
)
target_include_directories(flowcoin_mining PUBLIC src)
target_link_libraries(flowcoin_mining PUBLIC flowcoin_consensus flowcoin_chain flowcoin_crypto)

# --- flowcoin_script ---
add_library(flowcoin_script STATIC
    src/script/script.cpp
    src/script/standard.cpp
)
target_include_directories(flowcoin_script PUBLIC src)
target_link_libraries(flowcoin_script PUBLIC flowcoin_hash flowcoin_crypto)

# --- flowcoin_mempool ---
add_library(flowcoin_mempool STATIC
    src/mempool/mempool.cpp
    src/mempool/policy.cpp
)
target_include_directories(flowcoin_mempool PUBLIC src)
target_link_libraries(flowcoin_mempool PUBLIC flowcoin_chain flowcoin_crypto flowcoin_hash)

# --- flowcoin_index ---
add_library(flowcoin_index STATIC
    src/index/base.cpp
    src/index/txindex.cpp
    src/index/blockfilterindex.cpp
    src/index/coinstatsindex.cpp
)
target_include_directories(flowcoin_index PUBLIC src)
target_link_libraries(flowcoin_index PUBLIC flowcoin_chain flowcoin_hash sqlite)

# --- flowcoin_kernel ---
add_library(flowcoin_kernel STATIC
    src/kernel/context.cpp
    src/kernel/validation.cpp
    src/kernel/chainparams.cpp
    src/kernel/coinstats.cpp
    src/kernel/notifications.cpp
    src/kernel/chain_verifier.cpp
)
target_include_directories(flowcoin_kernel PUBLIC src)
target_link_libraries(flowcoin_kernel PUBLIC
    flowcoin_consensus flowcoin_chain flowcoin_crypto flowcoin_hash
    flowcoin_util flowcoin_common flowcoin_support
)

# --- flowcoin_policy ---
add_library(flowcoin_policy STATIC
    src/policy/policy.cpp
    src/policy/fees.cpp
    src/policy/rbf.cpp
)
target_include_directories(flowcoin_policy PUBLIC src)
target_link_libraries(flowcoin_policy PUBLIC flowcoin_mempool flowcoin_hash flowcoin_script)

# --- flowcoin_interfaces ---
add_library(flowcoin_interfaces STATIC
    src/interfaces/node.cpp
    src/interfaces/wallet.cpp
    src/interfaces/chain.cpp
    src/interfaces/handler.cpp
)
target_include_directories(flowcoin_interfaces PUBLIC src)
target_link_libraries(flowcoin_interfaces PUBLIC
    flowcoin_chain flowcoin_wallet flowcoin_mempool flowcoin_hash
)

# --- flowcoin_rest ---
add_library(flowcoin_rest STATIC
    src/rest.cpp
)
target_include_directories(flowcoin_rest PUBLIC src)
target_link_libraries(flowcoin_rest PUBLIC
    flowcoin_chain flowcoin_mempool flowcoin_hash json
)

# --- flowcoin_node ---
add_library(flowcoin_node STATIC
    src/node/context.cpp
    src/init.cpp
    src/config.cpp
    src/logging.cpp
)
target_include_directories(flowcoin_node PUBLIC src)
target_link_libraries(flowcoin_node PUBLIC
    flowcoin_rpc
    flowcoin_mining
    flowcoin_wallet
    flowcoin_net
    flowcoin_chain
    flowcoin_consensus
    flowcoin_mempool
    flowcoin_index
    flowcoin_kernel
    flowcoin_policy
    flowcoin_interfaces
    flowcoin_rest
    flowcoin_primitives
    flowcoin_crypto
    flowcoin_common
    flowcoin_hash
    flowcoin_util
    flowcoin_support
    flowcoin_compat
    json
    uv_a
)

# =============================================================================
# Executables
# =============================================================================

# --- flowcoind (full node daemon) ---
add_executable(flowcoind
    src/flowcoind.cpp
)
target_include_directories(flowcoind PRIVATE src)
target_link_libraries(flowcoind PRIVATE
    flowcoin_node
    flowcoin_mempool
    flowcoin_script
    flowcoin_rpc
    flowcoin_mining
    flowcoin_wallet
    flowcoin_net
    flowcoin_chain
    flowcoin_consensus
    flowcoin_kernel
    flowcoin_index
    flowcoin_policy
    flowcoin_interfaces
    flowcoin_rest
    flowcoin_primitives
    flowcoin_crypto
    flowcoin_common
    flowcoin_hash
    flowcoin_util
    flowcoin_support
    flowcoin_compat
    ggml
    sqlite
    ed25519
    xkcp
    zstd
    uv_a
    json
    pthread
    dl
    m
)

# --- flowcoin-cli (RPC client) ---
add_executable(flowcoin-cli
    src/flowcoin-cli.cpp
)
target_include_directories(flowcoin-cli PRIVATE src)
target_link_libraries(flowcoin-cli PRIVATE
    flowcoin_util
    flowcoin_hash
    json
    uv_a
    pthread
    dl
    m
)

# --- flowcoin-tx (offline transaction utility) ---
add_executable(flowcoin-tx
    src/flowcoin-tx.cpp
)
target_include_directories(flowcoin-tx PRIVATE src)
target_link_libraries(flowcoin-tx PRIVATE
    flowcoin_primitives
    flowcoin_crypto
    flowcoin_hash
    flowcoin_util
    ed25519
    xkcp
    zstd
    pthread
    dl
    m
)

# Mining is done via Python: tools/flowminer.py (PyTorch GPU)

# =============================================================================
# Tests (assert-based, no external framework required)
# =============================================================================
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_executable(flowcoin_tests
        src/test/test_main.cpp
        src/test/test_keccak.cpp
        src/test/test_arith_uint256.cpp
        src/test/test_ed25519.cpp
        src/test/test_slip0010.cpp
        src/test/test_bech32.cpp
        src/test/test_block_header.cpp
        src/test/test_transaction.cpp
        src/test/test_difficulty.cpp
        src/test/test_reward.cpp
        src/test/test_growth.cpp
        src/test/test_validation.cpp
        src/test/test_merkle.cpp
        src/test/test_serialize.cpp
        src/test/test_delta.cpp
        src/test/test_mempool.cpp
        src/test/test_script.cpp
        src/test/test_consensus_model.cpp
        src/test/test_eval_engine.cpp
        src/test/test_txindex.cpp
        src/test/test_sync.cpp
        src/test/test_fee_estimator.cpp
        src/test/test_txbuilder.cpp
        src/test/test_walletutil.cpp
        src/test/test_banman.cpp
        src/test/test_encryption.cpp
        src/test/test_keypool.cpp
        src/test/test_chaindb.cpp
        src/test/test_genesis.cpp
        src/test/test_rpc.cpp
        src/test/test_reorg.cpp
        src/test/test_compact_blocks.cpp
        src/test/test_netaddress.cpp
        src/test/test_wallet_full.cpp
        src/test/test_block_validation.cpp
        src/test/test_coin_selection.cpp
        src/test/test_strencodings.cpp
        src/test/test_transaction_ext.cpp
        src/test/test_backup.cpp
        src/test/test_threadpool.cpp
        src/test/test_fs.cpp
        src/test/test_logging.cpp
        src/test/test_random.cpp
        src/test/test_system.cpp
        src/test/test_config.cpp
        src/test/test_init.cpp
        src/test/test_blocktemplate.cpp
        src/test/test_submitblock.cpp
        src/test/test_compact_size.cpp
        src/test/test_delta_full.cpp
        src/test/test_pow.cpp
        src/test/test_integration.cpp
        src/test/test_aes256.cpp
        src/test/test_bloom.cpp
        src/test/test_script_interpreter.cpp
        src/test/test_mempool_advanced.cpp
        src/test/test_coinselect_algorithms.cpp
        src/test/test_hdchain.cpp
        src/test/test_walletdb_full.cpp
        src/test/test_rpc_handlers.cpp
        src/test/test_policy.cpp
        src/test/test_network_full.cpp
        src/test/test_block_connection.cpp
        src/test/test_reorg_full.cpp
        src/test/test_block_template_full.cpp
        src/test/test_inventory_relay.cpp
        src/test/test_bandwidth.cpp
        src/test/test_model_evaluation.cpp
        src/test/test_full_chain.cpp
        src/test/test_wallet_transactions.cpp
        src/test/test_mining_session.cpp
        src/test/test_protocol_spec.cpp
        src/test/test_inference.cpp
        src/test/test_chain_stats.cpp
        src/test/test_mutable_tx.cpp
        src/test/test_block_analysis.cpp
        src/test/test_wallet_advanced.cpp
        src/test/test_difficulty_analysis.cpp
        src/test/test_supply.cpp
        src/test/test_http_parser.cpp
        src/test/test_peer_scoring.cpp
    )
    target_include_directories(flowcoin_tests PRIVATE src)
    target_link_libraries(flowcoin_tests PRIVATE
        flowcoin_node
        flowcoin_mempool
        flowcoin_script
        flowcoin_rpc
        flowcoin_mining
        flowcoin_wallet
        flowcoin_net
        flowcoin_chain
        flowcoin_consensus
        flowcoin_kernel
        flowcoin_index
        flowcoin_policy
        flowcoin_interfaces
        flowcoin_rest
        flowcoin_primitives
        flowcoin_crypto
        flowcoin_common
        flowcoin_hash
        flowcoin_util
        flowcoin_support
        flowcoin_compat
        ggml
        sqlite
        ed25519
        xkcp
        zstd
        uv_a
        json
        pthread
        dl
        m
    )
    add_test(NAME flowcoin_tests COMMAND flowcoin_tests)
endif()

# =============================================================================
# Benchmarks
# =============================================================================
option(BUILD_BENCH "Build performance benchmarks" ON)
if(BUILD_BENCH)
    add_executable(flowcoin_bench
        src/bench/bench.cpp
        src/bench/bench_main.cpp
        src/bench/bench_keccak.cpp
        src/bench/bench_ed25519.cpp
        src/bench/bench_model.cpp
        src/bench/bench_chain.cpp
        src/bench/bench_script.cpp
        src/bench/bench_mempool.cpp
        src/bench/bench_crypto.cpp
        src/bench/bench_net.cpp
    )
    target_include_directories(flowcoin_bench PRIVATE src)
    target_link_libraries(flowcoin_bench PRIVATE
        flowcoin_node
        flowcoin_mempool
        flowcoin_script
        flowcoin_rpc
        flowcoin_mining
        flowcoin_wallet
        flowcoin_net
        flowcoin_chain
        flowcoin_consensus
        flowcoin_kernel
        flowcoin_primitives
        flowcoin_crypto
        flowcoin_common
        flowcoin_hash
        flowcoin_util
        flowcoin_support
        flowcoin_compat
        ggml
        sqlite
        ed25519
        xkcp
        zstd
        uv_a
        json
        pthread
        dl
        m
    )
endif()
