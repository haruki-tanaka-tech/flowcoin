// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Protocol specification compliance tests: block header size, unsigned
// portion size, hash computation, training hash, genesis block parameters,
// consensus parameter self-consistency, wire protocol header, and address
// encoding.

#include "consensus/difficulty.h"
#include "consensus/genesis.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "consensus/validation.h"
#include "crypto/bech32.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "net/protocol.h"
#include "primitives/block.h"
#include "util/arith_uint256.h"
#include "util/types.h"

#include <cassert>
#include <cmath>
#include <cstring>
#include <string>

using namespace flow;
using namespace flow::consensus;

void test_protocol_spec() {

    // -----------------------------------------------------------------------
    // Test 1: Block header is exactly 308 bytes
    // -----------------------------------------------------------------------
    {
        assert(BLOCK_HEADER_SIZE == 308);

        CBlockHeader hdr;
        auto full = hdr.serialize();
        assert(full.size() == 308);
    }

    // -----------------------------------------------------------------------
    // Test 2: Unsigned portion is exactly 244 bytes
    // -----------------------------------------------------------------------
    {
        assert(BLOCK_HEADER_UNSIGNED_SIZE == 244);

        CBlockHeader hdr;
        auto data = hdr.get_unsigned_data();
        assert(data.size() == 244);
    }

    // -----------------------------------------------------------------------
    // Test 3: Block hash = keccak256d(header[0..243])
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr;
        hdr.version = 1;
        hdr.height = 42;
        hdr.timestamp = GENESIS_TIMESTAMP;
        hdr.nbits = INITIAL_NBITS;
        hdr.nonce = 12345;

        auto unsigned_data = hdr.get_unsigned_data();
        assert(unsigned_data.size() == 244);

        // Compute keccak256d manually
        uint256 hash1 = keccak256(unsigned_data.data(), unsigned_data.size());
        uint256 hash2 = keccak256(hash1.data(), 32);

        // Should match get_hash()
        uint256 block_hash = hdr.get_hash();
        // keccak256d = keccak256(keccak256(data))
        assert(block_hash == hash2);
    }

    // -----------------------------------------------------------------------
    // Test 4: Training hash = keccak256(delta_hash || dataset_hash)
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr;
        hdr.version = 1;
        // Set training and dataset hashes
        GetRandBytes(hdr.training_hash.data(), 32);
        GetRandBytes(hdr.dataset_hash.data(), 32);

        // Compute training hash manually
        uint8_t combined[64];
        std::memcpy(combined, hdr.training_hash.data(), 32);
        std::memcpy(combined + 32, hdr.dataset_hash.data(), 32);
        uint256 expected = keccak256(combined, 64);

        // get_training_hash should produce this
        uint256 th = hdr.get_training_hash();
        assert(th == expected);
    }

    // -----------------------------------------------------------------------
    // Test 5: Genesis block matches hardcoded parameters
    // -----------------------------------------------------------------------
    {
        // Genesis timestamp
        assert(GENESIS_TIMESTAMP == 1742515200);

        // Genesis dimensions
        assert(GENESIS_D_MODEL == 512);
        assert(GENESIS_N_LAYERS == 8);
        assert(GENESIS_D_FF == 1024);
        assert(GENESIS_N_HEADS == 8);
        assert(GENESIS_D_HEAD == 64);
        assert(GENESIS_N_SLOTS == 1024);
        assert(GENESIS_GRU_DIM == 512);
        assert(GENESIS_VOCAB == 256);
        assert(GENESIS_SEQ_LEN == 256);
        assert(GENESIS_SEED == 42);
        assert(GENESIS_TOP_K == 2);
        assert(GENESIS_CONV_KERNEL == 4);

        // Derived relationships
        assert(GENESIS_D_HEAD == GENESIS_D_MODEL / GENESIS_N_HEADS);
        assert(GENESIS_D_FF == 2 * GENESIS_D_MODEL);
        assert(GENESIS_GRU_DIM == GENESIS_D_MODEL);
    }

    // -----------------------------------------------------------------------
    // Test 6: RETARGET_INTERVAL * TARGET_BLOCK_TIME == RETARGET_TIMESPAN
    // -----------------------------------------------------------------------
    {
        assert(RETARGET_INTERVAL == 2016);
        assert(TARGET_BLOCK_TIME == 600);
        assert(RETARGET_TIMESPAN == 1209600);
        assert(static_cast<int64_t>(RETARGET_INTERVAL) * TARGET_BLOCK_TIME == RETARGET_TIMESPAN);
    }

    // -----------------------------------------------------------------------
    // Test 7: HALVING_INTERVAL * INITIAL_REWARD / COIN gives expected supply
    // -----------------------------------------------------------------------
    {
        // First era produces HALVING_INTERVAL * INITIAL_REWARD
        int64_t era0_supply = static_cast<int64_t>(HALVING_INTERVAL) * INITIAL_REWARD;
        // 210,000 * 50 * 10^8 = 1.05 * 10^15
        assert(era0_supply == 210000LL * 50 * COIN);

        // Total supply converges to 21M
        assert(MAX_SUPPLY == 21'000'000LL * COIN);

        // Geometric series: sum = 210000 * 50 * 2 = 21000000
        // era0: 210000*50 = 10,500,000
        // era1: 210000*25 = 5,250,000
        // total converges to 21,000,000
        int64_t partial = 0;
        int64_t reward = INITIAL_REWARD;
        for (int era = 0; era < 64 && reward > 0; era++) {
            partial += static_cast<int64_t>(HALVING_INTERVAL) * reward;
            reward >>= 1;
        }
        // Should approach MAX_SUPPLY
        assert(partial <= MAX_SUPPLY);
        assert(partial > MAX_SUPPLY - COIN);  // within 1 FLOW
    }

    // -----------------------------------------------------------------------
    // Test 8: Growth schedule — continuous growth, dims freeze at 512
    // -----------------------------------------------------------------------
    {
        assert(DIM_FREEZE_HEIGHT == 512);
        assert(MAX_D_MODEL == 1024);
        assert(MAX_N_LAYERS == 24);
        assert(SLOT_GROWTH_PER_BLOCK == 4);
    }

    // -----------------------------------------------------------------------
    // Test 9: Wire protocol header = magic + command + size + checksum = 24 bytes
    // -----------------------------------------------------------------------
    {
        assert(MessageHeader::SIZE == 24);

        // Breakdown: 4 (magic) + 12 (command) + 4 (size) + 4 (checksum)
        assert(sizeof(uint32_t) + 12 + sizeof(uint32_t) + sizeof(uint32_t) == 24);

        // Verify by creating and serializing a header
        MessageHeader hdr;
        hdr.magic = MAINNET_MAGIC;
        std::memset(hdr.command, 0, 12);
        std::strncpy(hdr.command, "version", 12);
        hdr.payload_size = 0;
        hdr.checksum = 0;

        DataWriter w;
        hdr.serialize(w);
        assert(w.size() == 24);
    }

    // -----------------------------------------------------------------------
    // Test 10: Address format — "fl1" prefix, 42-62 chars total
    // -----------------------------------------------------------------------
    {
        // Generate a key and derive address
        auto kp = generate_keypair();
        auto pkh = keccak256(kp.pubkey.data(), 32);

        // Encode as bech32m
        std::string addr = bech32m_encode(MAINNET_HRP, pkh.data(), 32);
        assert(!addr.empty());

        // Must start with "fl1" (HRP "fl" + bech32m separator "1")
        assert(addr.substr(0, 3) == "fl1");

        // Length should be in range 42-62
        // "fl" (2) + "1" (1) + data chars + 6 checksum chars
        assert(addr.size() >= 42);
        assert(addr.size() <= 62);
    }

    // -----------------------------------------------------------------------
    // Test 11: Testnet and regtest address prefixes
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto pkh = keccak256(kp.pubkey.data(), 32);

        std::string testnet_addr = bech32m_encode(TESTNET_HRP, pkh.data(), 32);
        assert(testnet_addr.substr(0, 4) == "tfl1");

        std::string regtest_addr = bech32m_encode(REGTEST_HRP, pkh.data(), 32);
        assert(regtest_addr.substr(0, 4) == "rfl1");
    }

    // -----------------------------------------------------------------------
    // Test 12: Address round-trip (encode then decode)
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto pkh = keccak256(kp.pubkey.data(), 32);

        std::string addr = bech32m_encode(MAINNET_HRP, pkh.data(), 32);

        std::string hrp_out;
        std::vector<uint8_t> data_out;
        bool ok = bech32m_decode(addr, hrp_out, data_out);
        assert(ok);
        assert(hrp_out == MAINNET_HRP);
        assert(data_out.size() == 32);
        assert(std::memcmp(data_out.data(), pkh.data(), 32) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 13: Magic bytes are correct ASCII encodings
    // -----------------------------------------------------------------------
    {
        // MAINNET_MAGIC = "FLOW" = 0x464C4F57
        assert(MAINNET_MAGIC == 0x464C4F57);
        uint8_t magic_bytes[4];
        magic_bytes[0] = (MAINNET_MAGIC >> 24) & 0xFF;  // 'F' = 0x46
        magic_bytes[1] = (MAINNET_MAGIC >> 16) & 0xFF;  // 'L' = 0x4C
        magic_bytes[2] = (MAINNET_MAGIC >>  8) & 0xFF;  // 'O' = 0x4F
        magic_bytes[3] = (MAINNET_MAGIC >>  0) & 0xFF;  // 'W' = 0x57
        assert(magic_bytes[0] == 'F');
        assert(magic_bytes[1] == 'L');
        assert(magic_bytes[2] == 'O');
        assert(magic_bytes[3] == 'W');
    }

    // -----------------------------------------------------------------------
    // Test 14: COINBASE_MATURITY is 100
    // -----------------------------------------------------------------------
    {
        assert(COINBASE_MATURITY == 100);
    }

    // -----------------------------------------------------------------------
    // Test 15: Network port assignments
    // -----------------------------------------------------------------------
    {
        assert(MAINNET_PORT == 9333);
        assert(MAINNET_RPC_PORT == 9334);
        assert(TESTNET_PORT == 19333);
        assert(TESTNET_RPC_PORT == 19334);
        assert(REGTEST_PORT == 29333);
        assert(REGTEST_RPC_PORT == 29334);

        // All ports are different
        assert(MAINNET_PORT != TESTNET_PORT);
        assert(MAINNET_PORT != REGTEST_PORT);
        assert(TESTNET_PORT != REGTEST_PORT);
    }

    // -----------------------------------------------------------------------
    // Test 16: Protocol version
    // -----------------------------------------------------------------------
    {
        assert(PROTOCOL_VERSION == 1);
    }

    // -----------------------------------------------------------------------
    // Test 17: BIP44 coin type
    // -----------------------------------------------------------------------
    {
        assert(BIP44_COIN_TYPE == 9555);
    }

    // -----------------------------------------------------------------------
    // Test 18: Monetary policy constants
    // -----------------------------------------------------------------------
    {
        assert(COIN == 100'000'000LL);
        assert(MAX_SUPPLY == 2'100'000'000'000'000LL);
        assert(INITIAL_REWARD == 5'000'000'000LL);
        assert(HALVING_INTERVAL == 210'000);
        assert(MIN_REWARD == 1LL);
    }

    // -----------------------------------------------------------------------
    // Test 19: Block limits
    // -----------------------------------------------------------------------
    {
        assert(MAX_BLOCK_SIZE == 32'000'000);
        assert(MAX_TX_SIZE == 1'000'000);
        assert(MAX_BLOCK_SIGOPS == 80'000);
    }

    // -----------------------------------------------------------------------
    // Test 20: Training parameters
    // -----------------------------------------------------------------------
    {
        assert(EVAL_TOKENS == 4096);
        assert(EVAL_SEQ_LEN == 256);
        assert(MAX_VAL_LOSS == 100.0f);
        assert(MAX_LOSS_INCREASE == 2.0f);
        assert(MAX_DELTA_SIZE == 100'000'000);
        assert(MIN_DELTA_SIZE == 1);
        assert(MIN_TRAIN_STEPS_BASE == 1000);
    }

    // -----------------------------------------------------------------------
    // Test 21: Compute d_head helper
    // -----------------------------------------------------------------------
    {
        assert(compute_d_head(512, 8) == 64);
        assert(compute_d_head(1024, 16) == 64);
        assert(compute_d_head(640, 10) == 64);
        assert(compute_d_head(768, 12) == 64);
        assert(compute_d_head(100, 0) == 0);  // division by zero guard
    }

    // -----------------------------------------------------------------------
    // Test 22: is_valid_d_model and is_valid_n_layers
    // -----------------------------------------------------------------------
    {
        assert(is_valid_d_model(512));
        assert(is_valid_d_model(640));
        assert(is_valid_d_model(768));
        assert(is_valid_d_model(896));
        assert(is_valid_d_model(1024));
        assert(!is_valid_d_model(500));   // not multiple of 64
        assert(!is_valid_d_model(256));   // below minimum
        assert(!is_valid_d_model(2048));  // above maximum

        assert(is_valid_n_layers(8));
        assert(is_valid_n_layers(12));
        assert(is_valid_n_layers(16));
        assert(is_valid_n_layers(20));
        assert(is_valid_n_layers(24));
        assert(!is_valid_n_layers(7));    // not multiple of 4
        assert(!is_valid_n_layers(4));    // below minimum
        assert(!is_valid_n_layers(28));   // above maximum
    }

    // -----------------------------------------------------------------------
    // Test 23: Network limits
    // -----------------------------------------------------------------------
    {
        assert(MAX_OUTBOUND_PEERS == 8);
        assert(MAX_INBOUND_PEERS == 117);
        assert(MAX_PEERS == 125);
        assert(MAX_PEERS == MAX_OUTBOUND_PEERS + MAX_INBOUND_PEERS);
        assert(FINALITY_DEPTH == 6);
        assert(MAX_INV_SIZE == 50000);
        assert(ADDR_RELAY_MAX == 1000);
    }

    // -----------------------------------------------------------------------
    // Test 24: Pruning and IBD parameters
    // -----------------------------------------------------------------------
    {
        assert(MIN_BLOCKS_TO_KEEP == 288);
        assert(DEFAULT_PRUNE_TARGET_MB == 550);
        assert(IBD_MIN_BLOCKS_BEHIND == 144);
        assert(MAX_HEADERS_RESULTS == 2000);
        assert(MAX_BLOCKS_IN_TRANSIT == 16);
        assert(BLOCK_DOWNLOAD_TIMEOUT == 60);
    }

    // -----------------------------------------------------------------------
    // Test 25: Mempool limits
    // -----------------------------------------------------------------------
    {
        assert(MAX_MEMPOOL_SIZE == 300'000'000);
        assert(MIN_RELAY_FEE == 1000);
        assert(MEMPOOL_EXPIRY == 1'209'600);
    }

    // -----------------------------------------------------------------------
    // Test 26: Checkpoint interval
    // -----------------------------------------------------------------------
    {
        assert(CHECKPOINT_INTERVAL == 2016);
        assert(CHECKPOINT_INTERVAL == RETARGET_INTERVAL);
    }

    // -----------------------------------------------------------------------
    // Test 27: Genesis coinbase message
    // -----------------------------------------------------------------------
    {
        std::string msg = GENESIS_COINBASE_MSG;
        assert(!msg.empty());
        assert(msg.find("FlowCoin") != std::string::npos);
        assert(msg.find("2026") != std::string::npos);
    }

    // -----------------------------------------------------------------------
    // Test 28: MAX_BLOCK_WEIGHT and WITNESS_SCALE_FACTOR
    // -----------------------------------------------------------------------
    {
        assert(MAX_BLOCK_WEIGHT == 4'000'000);
        assert(WITNESS_SCALE_FACTOR == 4);
    }
}
