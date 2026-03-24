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
    src/ggml/ggml-alloc.c
    src/ggml/ggml-backend.cpp
    src/ggml/ggml-threading.cpp
    src/ggml/ggml-quants.c
    src/ggml/gguf.cpp
    src/ggml/ggml-cpu/ggml-cpu.c
    src/ggml/ggml-cpu/ggml-cpu.cpp
    src/ggml/ggml-cpu/ops.cpp
    src/ggml/ggml-cpu/vec.cpp
    src/ggml/ggml-cpu/unary-ops.cpp
    src/ggml/ggml-cpu/binary-ops.cpp
    src/ggml/ggml-cpu/quants.c
)
target_compile_definitions(ggml PUBLIC GGML_USE_CPU _GNU_SOURCE
    GGML_VERSION="0.0.0"
    GGML_COMMIT="flowcoin"
)
target_include_directories(ggml PUBLIC
    src/ggml
    src/ggml/ggml-cpu
)
# Suppress warnings and errors in vendored code
target_compile_options(ggml PRIVATE -w -Wno-error)
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

# --- flowcoin_util ---
add_library(flowcoin_util STATIC
    src/util/arith_uint256.cpp
    src/util/strencodings.cpp
    src/util/time.cpp
    src/util/random.cpp
)
target_include_directories(flowcoin_util PUBLIC src)
target_link_libraries(flowcoin_util PUBLIC xkcp)

# --- flowcoin_hash ---
add_library(flowcoin_hash STATIC
    src/hash/keccak.cpp
    src/hash/merkle.cpp
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
)
target_include_directories(flowcoin_crypto PUBLIC src)
target_link_libraries(flowcoin_crypto PUBLIC ed25519 flowcoin_hash)

# --- flowcoin_consensus ---
add_library(flowcoin_consensus STATIC
    src/consensus/validation.cpp
    src/consensus/difficulty.cpp
    src/consensus/reward.cpp
    src/consensus/growth.cpp
    src/consensus/merkle.cpp
    src/consensus/eval.cpp
    src/consensus/consensus_model.cpp
)
target_include_directories(flowcoin_consensus PUBLIC src)
target_link_libraries(flowcoin_consensus PUBLIC flowcoin_hash flowcoin_util ggml zstd)

# --- flowcoin_primitives ---
add_library(flowcoin_primitives STATIC
    src/primitives/block.cpp
    src/primitives/transaction.cpp
    src/primitives/delta.cpp
)
target_include_directories(flowcoin_primitives PUBLIC src)
target_link_libraries(flowcoin_primitives PUBLIC flowcoin_util zstd)

# --- flowcoin_chain ---
add_library(flowcoin_chain STATIC
    src/chain/chainstate.cpp
    src/chain/blockindex.cpp
    src/chain/blockstore.cpp
    src/chain/utxo.cpp
    src/chain/txindex.cpp
    src/chain/modelstate.cpp
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
)
target_include_directories(flowcoin_rpc PUBLIC src)
target_link_libraries(flowcoin_rpc PUBLIC
    flowcoin_chain flowcoin_wallet flowcoin_mempool flowcoin_net json uv_a
)

# --- flowcoin_mining ---
add_library(flowcoin_mining STATIC
    src/mining/blocktemplate.cpp
    src/mining/submitblock.cpp
)
target_include_directories(flowcoin_mining PUBLIC src)
target_link_libraries(flowcoin_mining PUBLIC flowcoin_consensus flowcoin_chain)

# --- flowcoin_script ---
add_library(flowcoin_script STATIC
    src/script/script.cpp
)
target_include_directories(flowcoin_script PUBLIC src)
target_link_libraries(flowcoin_script PUBLIC flowcoin_hash flowcoin_crypto)

# --- flowcoin_mempool ---
add_library(flowcoin_mempool STATIC
    src/mempool/mempool.cpp
)
target_include_directories(flowcoin_mempool PUBLIC src)
target_link_libraries(flowcoin_mempool PUBLIC flowcoin_chain flowcoin_crypto flowcoin_hash)

# --- flowcoin_node ---
add_library(flowcoin_node STATIC
    src/node/context.cpp
)
target_include_directories(flowcoin_node PUBLIC src)
target_link_libraries(flowcoin_node PUBLIC flowcoin_consensus)

# =============================================================================
# Executables
# =============================================================================

# --- flowcoind (full node daemon) ---
add_executable(flowcoind
    src/flowcoind.cpp
    src/init.cpp
    src/config.cpp
    src/logging.cpp
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
    flowcoin_primitives
    flowcoin_crypto
    flowcoin_hash
    flowcoin_util
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
        flowcoin_primitives
        flowcoin_crypto
        flowcoin_hash
        flowcoin_util
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
