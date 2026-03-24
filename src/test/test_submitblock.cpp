// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for block submission and deserialization (mining/submitblock.h).
// Tests block deserialization from raw bytes and structural validation
// without requiring a full ChainState.

#include "mining/submitblock.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "hash/merkle.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/serialize.h"
#include "util/types.h"

#include <cassert>
#include <cstring>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// Helper: serialize a block header into raw bytes (308 bytes total)
static std::vector<uint8_t> serialize_header(const CBlockHeader& hdr) {
    DataWriter w(512);

    w.write_bytes(hdr.prev_hash.data(), 32);
    w.write_bytes(hdr.merkle_root.data(), 32);
    w.write_bytes(hdr.training_hash.data(), 32);
    w.write_bytes(hdr.dataset_hash.data(), 32);
    w.write_u64_le(hdr.height);
    w.write_i64_le(hdr.timestamp);
    w.write_u32_le(hdr.nbits);
    w.write_float_le(hdr.val_loss);
    w.write_float_le(hdr.prev_val_loss);
    w.write_u32_le(hdr.d_model);
    w.write_u32_le(hdr.n_layers);
    w.write_u32_le(hdr.d_ff);
    w.write_u32_le(hdr.n_heads);
    w.write_u32_le(hdr.gru_dim);
    w.write_u32_le(hdr.n_slots);
    w.write_u32_le(hdr.train_steps);
    w.write_u32_le(hdr.stagnation);
    w.write_u32_le(hdr.delta_offset);
    w.write_u32_le(hdr.delta_length);
    w.write_u32_le(hdr.sparse_count);
    w.write_float_le(hdr.sparse_threshold);
    w.write_u32_le(hdr.nonce);
    w.write_u32_le(hdr.version);
    w.write_bytes(hdr.miner_pubkey.data(), 32);
    w.write_bytes(hdr.miner_sig.data(), 64);

    return w.release();
}

// Helper: create a signed genesis-like block header
static CBlockHeader make_signed_header() {
    auto kp = generate_keypair();
    auto dims = compute_growth(0, 0);

    CBlockHeader hdr;
    hdr.height = 0;
    hdr.timestamp = GENESIS_TIMESTAMP;
    hdr.nbits = INITIAL_NBITS;
    hdr.val_loss = 5.0f;
    hdr.prev_val_loss = 0.0f;
    hdr.d_model = dims.d_model;
    hdr.n_layers = dims.n_layers;
    hdr.d_ff = dims.d_ff;
    hdr.n_heads = dims.n_heads;
    hdr.gru_dim = dims.gru_dim;
    hdr.n_slots = dims.n_slots;
    hdr.train_steps = 5000;
    hdr.version = 1;
    hdr.stagnation = 0;
    hdr.nonce = 0;

    std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
    auto unsigned_data = hdr.get_unsigned_data();
    auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                            kp.privkey.data(), kp.pubkey.data());
    std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

    return hdr;
}

void test_submitblock() {
    // -----------------------------------------------------------------------
    // Test 1: Deserialize a header-only block (308 bytes, no body)
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();
        auto raw = serialize_header(hdr);
        assert(raw.size() == 308);

        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);
        assert(block.height == hdr.height);
        assert(block.timestamp == hdr.timestamp);
        assert(block.nbits == hdr.nbits);
        assert(block.val_loss == hdr.val_loss);
        assert(block.prev_val_loss == hdr.prev_val_loss);
        assert(block.d_model == hdr.d_model);
        assert(block.n_layers == hdr.n_layers);
        assert(block.d_ff == hdr.d_ff);
        assert(block.n_heads == hdr.n_heads);
        assert(block.gru_dim == hdr.gru_dim);
        assert(block.n_slots == hdr.n_slots);
        assert(block.train_steps == hdr.train_steps);
        assert(block.version == hdr.version);
        assert(block.nonce == hdr.nonce);
    }

    // -----------------------------------------------------------------------
    // Test 2: Reject data shorter than header size
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> too_short(307, 0);
        CBlock block;
        bool ok = deserialize_block(too_short, block);
        assert(!ok);
    }

    // -----------------------------------------------------------------------
    // Test 3: Reject empty data
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> empty;
        CBlock block;
        bool ok = deserialize_block(empty, block);
        assert(!ok);
    }

    // -----------------------------------------------------------------------
    // Test 4: Deserialize block with transactions
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();
        auto raw = serialize_header(hdr);

        // Append transaction data: 1 coinbase transaction
        DataWriter w;

        // Transaction count
        w.write_compact_size(1);

        // Transaction: version
        w.write_u32_le(1);

        // vin count = 1
        w.write_compact_size(1);

        // vin[0]: null prevout (coinbase)
        uint8_t null_txid[32] = {};
        w.write_bytes(null_txid, 32);
        w.write_u32_le(0);  // index

        // pubkey
        uint8_t zero_pk[32] = {};
        w.write_bytes(zero_pk, 32);

        // signature
        uint8_t zero_sig[64] = {};
        w.write_bytes(zero_sig, 64);

        // vout count = 1
        w.write_compact_size(1);

        // vout[0]: amount + pubkey_hash
        w.write_i64_le(50 * COIN);
        uint8_t zero_pkh[32] = {};
        w.write_bytes(zero_pkh, 32);

        // locktime
        w.write_i64_le(0);

        // delta payload length = 0
        w.write_compact_size(0);

        // Combine header + body
        auto body = w.release();
        raw.insert(raw.end(), body.begin(), body.end());

        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);
        assert(block.vtx.size() == 1);
        assert(block.vtx[0].is_coinbase());
        assert(block.vtx[0].vout.size() == 1);
        assert(block.vtx[0].vout[0].amount == 50 * COIN);
        assert(block.delta_payload.empty());
    }

    // -----------------------------------------------------------------------
    // Test 5: Deserialize block with delta payload
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();
        auto raw = serialize_header(hdr);

        DataWriter w;
        // No transactions
        w.write_compact_size(0);

        // Delta payload: 10 bytes
        std::vector<uint8_t> delta = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        w.write_compact_size(delta.size());
        w.write_bytes(delta.data(), delta.size());

        auto body = w.release();
        raw.insert(raw.end(), body.begin(), body.end());

        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);
        assert(block.vtx.empty());
        assert(block.delta_payload.size() == 10);
        assert(block.delta_payload == delta);
    }

    // -----------------------------------------------------------------------
    // Test 6: Deserialized header fields match original
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();
        hdr.height = 42;
        hdr.nonce = 12345;
        hdr.train_steps = 9999;

        // Re-sign after changes
        auto kp = generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto unsigned_data = hdr.get_unsigned_data();
        auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                                kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        auto raw = serialize_header(hdr);
        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);
        assert(block.height == 42);
        assert(block.nonce == 12345);
        assert(block.train_steps == 9999);
    }

    // -----------------------------------------------------------------------
    // Test 7: Miner pubkey and signature preserved through serialization
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();
        auto raw = serialize_header(hdr);

        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);

        // Compare pubkey bytes
        assert(std::memcmp(block.miner_pubkey.data(),
                            hdr.miner_pubkey.data(), 32) == 0);
        // Compare signature bytes
        assert(std::memcmp(block.miner_sig.data(),
                            hdr.miner_sig.data(), 64) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 8: SubmitResult struct works correctly
    // -----------------------------------------------------------------------
    {
        SubmitResult ok_result;
        ok_result.accepted = true;
        ok_result.reject_reason.clear();
        assert(ok_result.accepted);
        assert(ok_result.reject_reason.empty());

        SubmitResult bad_result;
        bad_result.accepted = false;
        bad_result.reject_reason = "bad-height";
        assert(!bad_result.accepted);
        assert(bad_result.reject_reason == "bad-height");
    }

    // -----------------------------------------------------------------------
    // Test 9: Block with multiple transactions deserializes
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();
        auto raw = serialize_header(hdr);

        DataWriter w;
        // 2 transactions
        w.write_compact_size(2);

        // Transaction 1 (coinbase)
        w.write_u32_le(1);  // version
        w.write_compact_size(1);  // 1 input
        uint8_t zeros[32] = {};
        w.write_bytes(zeros, 32);  // null txid
        w.write_u32_le(0);         // index
        w.write_bytes(zeros, 32);  // pubkey
        uint8_t zero_sig[64] = {};
        w.write_bytes(zero_sig, 64);  // sig
        w.write_compact_size(1);  // 1 output
        w.write_i64_le(50 * COIN);
        w.write_bytes(zeros, 32);
        w.write_i64_le(0);  // locktime

        // Transaction 2 (regular)
        w.write_u32_le(1);  // version
        w.write_compact_size(1);  // 1 input
        uint8_t fake_txid[32] = {0x01};
        w.write_bytes(fake_txid, 32);
        w.write_u32_le(0);
        w.write_bytes(zeros, 32);
        w.write_bytes(zero_sig, 64);
        w.write_compact_size(1);  // 1 output
        w.write_i64_le(10 * COIN);
        w.write_bytes(zeros, 32);
        w.write_i64_le(0);

        // No delta
        w.write_compact_size(0);

        auto body = w.release();
        raw.insert(raw.end(), body.begin(), body.end());

        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);
        assert(block.vtx.size() == 2);
        assert(block.vtx[0].is_coinbase());
        assert(!block.vtx[1].is_coinbase());
    }

    // -----------------------------------------------------------------------
    // Test 10: Deserialized block hash matches original
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();
        uint256 original_hash = hdr.get_hash();

        auto raw = serialize_header(hdr);
        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);

        uint256 deser_hash = block.get_hash();
        assert(deser_hash == original_hash);
    }

    // -----------------------------------------------------------------------
    // Test 11: Deserialize block with multiple outputs per transaction
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();
        auto raw = serialize_header(hdr);

        DataWriter w;
        w.write_compact_size(1);  // 1 transaction

        // Transaction with 3 outputs
        w.write_u32_le(1);  // version
        w.write_compact_size(1);  // 1 input

        uint8_t zeros[32] = {};
        w.write_bytes(zeros, 32);  // null txid
        w.write_u32_le(0);
        w.write_bytes(zeros, 32);  // pubkey
        uint8_t zero_sig[64] = {};
        w.write_bytes(zero_sig, 64);

        w.write_compact_size(3);  // 3 outputs
        w.write_i64_le(25 * COIN);
        w.write_bytes(zeros, 32);
        w.write_i64_le(15 * COIN);
        w.write_bytes(zeros, 32);
        w.write_i64_le(10 * COIN);
        w.write_bytes(zeros, 32);

        w.write_i64_le(0);  // locktime

        w.write_compact_size(0);  // no delta

        auto body = w.release();
        raw.insert(raw.end(), body.begin(), body.end());

        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);
        assert(block.vtx.size() == 1);
        assert(block.vtx[0].vout.size() == 3);
        assert(block.vtx[0].vout[0].amount == 25 * COIN);
        assert(block.vtx[0].vout[1].amount == 15 * COIN);
        assert(block.vtx[0].vout[2].amount == 10 * COIN);
        assert(block.vtx[0].get_value_out() == 50 * COIN);
    }

    // -----------------------------------------------------------------------
    // Test 12: Deserialize block with multiple inputs
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();
        auto raw = serialize_header(hdr);

        DataWriter w;
        w.write_compact_size(1);  // 1 transaction

        w.write_u32_le(1);  // version
        w.write_compact_size(2);  // 2 inputs

        // Input 1
        uint8_t txid1[32] = {0x01};
        w.write_bytes(txid1, 32);
        w.write_u32_le(0);
        uint8_t pk1[32] = {0xAA};
        w.write_bytes(pk1, 32);
        uint8_t sig1[64] = {0xBB};
        w.write_bytes(sig1, 64);

        // Input 2
        uint8_t txid2[32] = {0x02};
        w.write_bytes(txid2, 32);
        w.write_u32_le(1);
        uint8_t pk2[32] = {0xCC};
        w.write_bytes(pk2, 32);
        uint8_t sig2[64] = {0xDD};
        w.write_bytes(sig2, 64);

        w.write_compact_size(1);  // 1 output
        w.write_i64_le(100 * COIN);
        uint8_t zeros[32] = {};
        w.write_bytes(zeros, 32);

        w.write_i64_le(0);  // locktime

        w.write_compact_size(0);  // no delta

        auto body = w.release();
        raw.insert(raw.end(), body.begin(), body.end());

        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);
        assert(block.vtx.size() == 1);
        assert(block.vtx[0].vin.size() == 2);
        assert(block.vtx[0].vin[0].prevout.index == 0);
        assert(block.vtx[0].vin[1].prevout.index == 1);
    }

    // -----------------------------------------------------------------------
    // Test 13: Serialize header preserves all numeric fields
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();
        hdr.delta_offset = 12345;
        hdr.delta_length = 67890;
        hdr.sparse_count = 4242;
        hdr.sparse_threshold = 0.005f;

        auto kp = generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto unsigned_data = hdr.get_unsigned_data();
        auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                                kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        auto raw = serialize_header(hdr);
        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);

        assert(block.delta_offset == 12345);
        assert(block.delta_length == 67890);
        assert(block.sparse_count == 4242);
        assert(block.sparse_threshold == 0.005f);
    }

    // -----------------------------------------------------------------------
    // Test 14: Serialize header preserves all hash fields
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();

        // Set random hash values
        flow::GetRandBytes(hdr.prev_hash.data(), 32);
        flow::GetRandBytes(hdr.merkle_root.data(), 32);
        flow::GetRandBytes(hdr.training_hash.data(), 32);
        flow::GetRandBytes(hdr.dataset_hash.data(), 32);

        auto kp = generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto unsigned_data = hdr.get_unsigned_data();
        auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                                kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        auto raw = serialize_header(hdr);
        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);

        assert(block.prev_hash == hdr.prev_hash);
        assert(block.merkle_root == hdr.merkle_root);
        assert(block.training_hash == hdr.training_hash);
        assert(block.dataset_hash == hdr.dataset_hash);
    }

    // -----------------------------------------------------------------------
    // Test 15: Deserialized val_loss preserves float precision
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_signed_header();
        hdr.val_loss = 3.14159f;
        hdr.prev_val_loss = 3.51927f;

        auto kp = generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto unsigned_data = hdr.get_unsigned_data();
        auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                                kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        auto raw = serialize_header(hdr);
        CBlock block;
        bool ok = deserialize_block(raw, block);
        assert(ok);

        // Bit-exact float comparison
        uint32_t orig_bits, deser_bits;
        std::memcpy(&orig_bits, &hdr.val_loss, 4);
        std::memcpy(&deser_bits, &block.val_loss, 4);
        assert(orig_bits == deser_bits);

        std::memcpy(&orig_bits, &hdr.prev_val_loss, 4);
        std::memcpy(&deser_bits, &block.prev_val_loss, 4);
        assert(orig_bits == deser_bits);
    }
}
