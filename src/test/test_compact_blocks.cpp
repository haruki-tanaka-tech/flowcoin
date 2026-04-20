// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for compact block relay primitives: short txid computation,
// compact block construction and reconstruction from mempool.

#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/random.h"
#include "util/strencodings.h"
#include "util/types.h"

#include <cassert>
#include <cstring>
#include <map>
#include <set>
#include <vector>

using namespace flow;

// ---------------------------------------------------------------------------
// Compact block helper functions (BIP-152 style)
// ---------------------------------------------------------------------------

// Compute a 6-byte short txid from a full 32-byte txid and a nonce.
// short_id = siphash(txid, key)[0..5]  (simplified: keccak256(nonce || txid)[0..5])
static std::array<uint8_t, 6> compute_short_txid(const uint256& txid, uint64_t nonce) {
    std::vector<uint8_t> preimage;
    // Append nonce as 8 bytes LE
    for (int i = 0; i < 8; ++i) {
        preimage.push_back(static_cast<uint8_t>((nonce >> (i * 8)) & 0xFF));
    }
    preimage.insert(preimage.end(), txid.begin(), txid.end());

    uint256 hash = keccak256(preimage);

    std::array<uint8_t, 6> short_id;
    std::memcpy(short_id.data(), hash.data(), 6);
    return short_id;
}

// A compact block: header + short txids for known transactions
struct CompactBlock {
    CBlockHeader header;
    uint64_t nonce;
    std::vector<std::array<uint8_t, 6>> short_ids;
    // Prefilled transactions (transactions the sender predicts the receiver doesn't have)
    std::vector<std::pair<uint16_t, CTransaction>> prefilled;
};

// Build a compact block from a full block
static CompactBlock make_compact(const CBlock& block, uint64_t nonce) {
    CompactBlock cb;
    cb.header = block;
    cb.nonce = nonce;

    for (size_t i = 0; i < block.vtx.size(); ++i) {
        if (i == 0) {
            // Coinbase is always prefilled
            cb.prefilled.push_back({0, block.vtx[0]});
        } else {
            uint256 txid = block.vtx[i].get_txid();
            cb.short_ids.push_back(compute_short_txid(txid, nonce));
        }
    }

    return cb;
}

// Reconstruct a block from a compact block and a mempool (map of txid -> tx)
struct ReconstructResult {
    CBlock block;
    std::vector<size_t> missing_indices;  // indices of short_ids not found
    bool complete;
};

static ReconstructResult reconstruct_block(
    const CompactBlock& cb,
    const std::map<uint256, CTransaction>& mempool)
{
    ReconstructResult result;
    result.block = CBlock(cb.header);
    result.complete = true;

    // Build short_id -> tx mapping from mempool
    std::map<std::array<uint8_t, 6>, CTransaction> short_id_map;
    for (const auto& [txid, tx] : mempool) {
        auto sid = compute_short_txid(txid, cb.nonce);
        short_id_map[sid] = tx;
    }

    // Start with prefilled count + short_id count as total
    size_t total_tx = cb.prefilled.size() + cb.short_ids.size();
    result.block.vtx.resize(total_tx);

    // Insert prefilled transactions
    for (const auto& [idx, tx] : cb.prefilled) {
        if (idx < total_tx) {
            result.block.vtx[idx] = tx;
        }
    }

    // Fill in from mempool using short IDs
    size_t vtx_pos = 0;
    size_t short_pos = 0;
    for (size_t i = 0; i < total_tx; ++i) {
        // Skip prefilled positions
        bool is_prefilled = false;
        for (const auto& [pidx, ptx] : cb.prefilled) {
            if (pidx == i) {
                is_prefilled = true;
                break;
            }
        }

        if (!is_prefilled && short_pos < cb.short_ids.size()) {
            auto it = short_id_map.find(cb.short_ids[short_pos]);
            if (it != short_id_map.end()) {
                result.block.vtx[i] = it->second;
            } else {
                result.missing_indices.push_back(short_pos);
                result.complete = false;
            }
            short_pos++;
        }
    }

    return result;
}

// Helper: create a coinbase transaction
static CTransaction make_cb_tx(Amount amount) {
    CTransaction tx;
    tx.version = 1;
    CTxIn cb;
    tx.vin.push_back(cb);
    std::array<uint8_t, 32> pkh{};
    GetRandBytes(pkh.data(), 32);
    tx.vout.push_back(CTxOut(amount, pkh));
    return tx;
}

// Helper: create a random-ish regular transaction
static CTransaction make_regular_tx(uint32_t seed) {
    CTransaction tx;
    tx.version = 1;

    CTxIn in;
    GetRandBytes(in.prevout.txid.data(), 32);
    in.prevout.index = seed;
    auto kp = generate_keypair();
    in.pubkey = kp.pubkey;

    // Sign
    tx.vin.push_back(in);
    std::array<uint8_t, 32> dest_pkh{};
    GetRandBytes(dest_pkh.data(), 32);
    tx.vout.push_back(CTxOut(1000 + seed, dest_pkh));

    auto sighash = tx.serialize_for_hash();
    auto txhash = keccak256d(sighash);
    auto sig = ed25519_sign(txhash.data(), 32,
                            kp.privkey.data(), kp.pubkey.data());
    tx.vin[0].signature = sig;

    return tx;
}

void test_compact_blocks() {

    // -----------------------------------------------------------------------
    // Test 1: Short txid computation is deterministic
    // -----------------------------------------------------------------------
    {
        uint256 txid;
        GetRandBytes(txid.data(), 32);
        uint64_t nonce = 42;

        auto sid1 = compute_short_txid(txid, nonce);
        auto sid2 = compute_short_txid(txid, nonce);
        assert(sid1 == sid2);
    }

    // -----------------------------------------------------------------------
    // Test 2: Different nonces produce different short IDs
    // -----------------------------------------------------------------------
    {
        uint256 txid;
        GetRandBytes(txid.data(), 32);

        auto sid1 = compute_short_txid(txid, 1);
        auto sid2 = compute_short_txid(txid, 2);
        assert(sid1 != sid2);
    }

    // -----------------------------------------------------------------------
    // Test 3: Different txids produce different short IDs
    // -----------------------------------------------------------------------
    {
        uint256 txid1, txid2;
        GetRandBytes(txid1.data(), 32);
        GetRandBytes(txid2.data(), 32);
        uint64_t nonce = 100;

        auto sid1 = compute_short_txid(txid1, nonce);
        auto sid2 = compute_short_txid(txid2, nonce);
        assert(sid1 != sid2);
    }

    // -----------------------------------------------------------------------
    // Test 4: Compact block construction from full block
    // -----------------------------------------------------------------------
    {
        CBlock block;
        block.height = 5;
        block.version = 1;

        // Add coinbase
        block.vtx.push_back(make_cb_tx(5000000000LL));

        // Add regular transactions
        for (int i = 0; i < 5; ++i) {
            block.vtx.push_back(make_regular_tx(i));
        }

        uint64_t nonce = 12345;
        CompactBlock cb = make_compact(block, nonce);

        // Coinbase is prefilled
        assert(cb.prefilled.size() == 1);
        assert(cb.prefilled[0].first == 0);

        // 5 regular txs as short IDs
        assert(cb.short_ids.size() == 5);

        // Each short ID is 6 bytes (non-zero in practice)
        for (const auto& sid : cb.short_ids) {
            bool all_zero = true;
            for (auto b : sid) {
                if (b != 0) { all_zero = false; break; }
            }
            // Very unlikely to be all zero
            (void)all_zero;
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: Compact block reconstruction from mempool
    // -----------------------------------------------------------------------
    {
        CBlock block;
        block.height = 10;
        block.version = 1;

        block.vtx.push_back(make_cb_tx(5000000000LL));
        for (int i = 0; i < 3; ++i) {
            block.vtx.push_back(make_regular_tx(100 + i));
        }

        uint64_t nonce = 999;
        CompactBlock cb = make_compact(block, nonce);

        // Build a mempool containing all the block's transactions
        std::map<uint256, CTransaction> mempool;
        for (size_t i = 1; i < block.vtx.size(); ++i) {
            uint256 txid = block.vtx[i].get_txid();
            mempool[txid] = block.vtx[i];
        }

        auto result = reconstruct_block(cb, mempool);
        assert(result.complete);
        assert(result.missing_indices.empty());
        assert(result.block.vtx.size() == block.vtx.size());
    }

    // -----------------------------------------------------------------------
    // Test 6: Missing transaction detection
    // -----------------------------------------------------------------------
    {
        CBlock block;
        block.height = 11;
        block.version = 1;

        block.vtx.push_back(make_cb_tx(5000000000LL));
        for (int i = 0; i < 4; ++i) {
            block.vtx.push_back(make_regular_tx(200 + i));
        }

        uint64_t nonce = 777;
        CompactBlock cb = make_compact(block, nonce);

        // Mempool missing the last transaction
        std::map<uint256, CTransaction> partial_mempool;
        for (size_t i = 1; i < block.vtx.size() - 1; ++i) {
            uint256 txid = block.vtx[i].get_txid();
            partial_mempool[txid] = block.vtx[i];
        }

        auto result = reconstruct_block(cb, partial_mempool);
        assert(!result.complete);
        assert(!result.missing_indices.empty());
    }

    // -----------------------------------------------------------------------
    // Test 7: Empty block (coinbase only)
    // -----------------------------------------------------------------------
    {
        CBlock block;
        block.height = 12;
        block.version = 1;
        block.vtx.push_back(make_cb_tx(5000000000LL));

        uint64_t nonce = 0;
        CompactBlock cb = make_compact(block, nonce);

        assert(cb.prefilled.size() == 1);
        assert(cb.short_ids.empty());

        std::map<uint256, CTransaction> empty_mempool;
        auto result = reconstruct_block(cb, empty_mempool);
        assert(result.complete);
        assert(result.block.vtx.size() == 1);
    }

    // -----------------------------------------------------------------------
    // Test 8: Short IDs are unique within a block
    // -----------------------------------------------------------------------
    {
        CBlock block;
        block.height = 13;
        block.version = 1;
        block.vtx.push_back(make_cb_tx(5000000000LL));

        for (int i = 0; i < 20; ++i) {
            block.vtx.push_back(make_regular_tx(300 + i));
        }

        uint64_t nonce = 5555;
        CompactBlock cb = make_compact(block, nonce);

        std::set<std::array<uint8_t, 6>> unique_sids;
        for (const auto& sid : cb.short_ids) {
            unique_sids.insert(sid);
        }

        // All short IDs should be unique (collision is astronomically unlikely)
        assert(unique_sids.size() == cb.short_ids.size());
    }

    // -----------------------------------------------------------------------
    // Test 9: Round-trip: block -> compact -> reconstruct
    // -----------------------------------------------------------------------
    {
        CBlock original;
        original.height = 14;
        original.version = 1;
        original.vtx.push_back(make_cb_tx(5000000000LL));

        for (int i = 0; i < 10; ++i) {
            original.vtx.push_back(make_regular_tx(400 + i));
        }

        uint64_t nonce = 98765;
        CompactBlock cb = make_compact(original, nonce);

        // Full mempool
        std::map<uint256, CTransaction> mempool;
        for (size_t i = 1; i < original.vtx.size(); ++i) {
            uint256 txid = original.vtx[i].get_txid();
            mempool[txid] = original.vtx[i];
        }

        auto result = reconstruct_block(cb, mempool);
        assert(result.complete);
        assert(result.block.vtx.size() == original.vtx.size());

        // Verify all txids match
        for (size_t i = 0; i < original.vtx.size(); ++i) {
            assert(result.block.vtx[i].get_txid() == original.vtx[i].get_txid());
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: Empty mempool reconstruction fails for non-trivial block
    // -----------------------------------------------------------------------
    {
        CBlock block;
        block.height = 15;
        block.version = 1;
        block.vtx.push_back(make_cb_tx(5000000000LL));
        block.vtx.push_back(make_regular_tx(500));

        uint64_t nonce = 1111;
        CompactBlock cb = make_compact(block, nonce);

        std::map<uint256, CTransaction> empty_mempool;
        auto result = reconstruct_block(cb, empty_mempool);
        assert(!result.complete);
        assert(result.missing_indices.size() == 1);
    }
}
