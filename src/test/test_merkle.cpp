// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "hash/merkle.h"
#include "hash/keccak.h"
#include "consensus/merkle.h"
#include "primitives/transaction.h"
#include <cassert>
#include <cstring>
#include <stdexcept>

void test_merkle() {
    // Empty list: returns null hash
    {
        std::vector<flow::uint256> empty;
        auto root = flow::compute_merkle_root(empty);
        assert(root.is_null());
    }

    // Single leaf: returns the leaf itself
    {
        flow::uint256 leaf;
        leaf[0] = 0x42;
        leaf[15] = 0xAB;
        std::vector<flow::uint256> leaves = {leaf};
        auto root = flow::compute_merkle_root(leaves);
        assert(root == leaf);
    }

    // Two leaves: root = keccak256d(left || right)
    {
        flow::uint256 a, b;
        a[0] = 0x01;
        b[0] = 0x02;

        uint8_t combined[64];
        std::memcpy(combined, a.data(), 32);
        std::memcpy(combined + 32, b.data(), 32);
        auto expected = flow::keccak256d(combined, 64);

        std::vector<flow::uint256> leaves = {a, b};
        auto root = flow::compute_merkle_root(leaves);
        assert(root == expected);
    }

    // Three leaves: last is duplicated, then tree of 4
    // Level 0: [A, B, C, C]
    // Level 1: [H(A||B), H(C||C)]
    // Level 2: H(H(A||B) || H(C||C))
    {
        flow::uint256 a, b, c;
        a[0] = 0x10;
        b[0] = 0x20;
        c[0] = 0x30;

        // H(A||B)
        uint8_t ab[64];
        std::memcpy(ab, a.data(), 32);
        std::memcpy(ab + 32, b.data(), 32);
        auto hab = flow::keccak256d(ab, 64);

        // H(C||C)
        uint8_t cc[64];
        std::memcpy(cc, c.data(), 32);
        std::memcpy(cc + 32, c.data(), 32);
        auto hcc = flow::keccak256d(cc, 64);

        // Root = H(H(A||B) || H(C||C))
        uint8_t top[64];
        std::memcpy(top, hab.data(), 32);
        std::memcpy(top + 32, hcc.data(), 32);
        auto expected = flow::keccak256d(top, 64);

        std::vector<flow::uint256> leaves = {a, b, c};
        auto root = flow::compute_merkle_root(leaves);
        assert(root == expected);
    }

    // Four leaves: balanced tree
    // Level 0: [A, B, C, D]
    // Level 1: [H(A||B), H(C||D)]
    // Level 2: H(H(A||B) || H(C||D))
    {
        flow::uint256 a, b, c, d;
        a[0] = 0xAA;
        b[0] = 0xBB;
        c[0] = 0xCC;
        d[0] = 0xDD;

        uint8_t ab[64], cd[64];
        std::memcpy(ab, a.data(), 32);
        std::memcpy(ab + 32, b.data(), 32);
        auto hab = flow::keccak256d(ab, 64);

        std::memcpy(cd, c.data(), 32);
        std::memcpy(cd + 32, d.data(), 32);
        auto hcd = flow::keccak256d(cd, 64);

        uint8_t top[64];
        std::memcpy(top, hab.data(), 32);
        std::memcpy(top + 32, hcd.data(), 32);
        auto expected = flow::keccak256d(top, 64);

        std::vector<flow::uint256> leaves = {a, b, c, d};
        auto root = flow::compute_merkle_root(leaves);
        assert(root == expected);
    }

    // Five leaves: odd, last duplicated to make 6
    {
        std::vector<flow::uint256> leaves(5);
        for (int i = 0; i < 5; i++) {
            leaves[i][0] = static_cast<uint8_t>(i + 1);
        }
        auto root = flow::compute_merkle_root(leaves);
        assert(!root.is_null());

        // Root should be deterministic
        auto root2 = flow::compute_merkle_root(leaves);
        assert(root == root2);
    }

    // Merkle root is order-dependent: swapping leaves changes root
    {
        flow::uint256 a, b;
        a[0] = 0x01;
        b[0] = 0x02;

        auto root_ab = flow::compute_merkle_root({a, b});
        auto root_ba = flow::compute_merkle_root({b, a});
        assert(root_ab != root_ba);
    }

    // compute_block_merkle_root with transactions
    {
        // Single coinbase transaction
        flow::CTransaction coinbase;
        flow::CTxIn cb_in;
        coinbase.vin.push_back(cb_in);
        coinbase.vout.push_back(flow::CTxOut(50 * 100000000LL, {}));

        std::vector<flow::CTransaction> vtx = {coinbase};
        auto root = flow::consensus::compute_block_merkle_root(vtx);

        // Should equal the coinbase txid (single leaf)
        assert(root == coinbase.get_txid());
    }

    // Two transactions: coinbase + regular
    {
        flow::CTransaction coinbase;
        flow::CTxIn cb_in;
        coinbase.vin.push_back(cb_in);
        coinbase.vout.push_back(flow::CTxOut(50 * 100000000LL, {}));

        flow::CTransaction tx;
        flow::uint256 prev;
        prev[0] = 0xFF;
        tx.vin.push_back(flow::CTxIn(flow::COutPoint(prev, 0), {}, {}));
        tx.vout.push_back(flow::CTxOut(10 * 100000000LL, {}));

        std::vector<flow::CTransaction> vtx = {coinbase, tx};
        auto root = flow::consensus::compute_block_merkle_root(vtx);

        // Should be keccak256d(coinbase_txid || tx_txid)
        uint8_t combined[64];
        auto id1 = coinbase.get_txid();
        auto id2 = tx.get_txid();
        std::memcpy(combined, id1.data(), 32);
        std::memcpy(combined + 32, id2.data(), 32);
        auto expected = flow::keccak256d(combined, 64);
        assert(root == expected);
    }

    // Empty transaction list
    {
        std::vector<flow::CTransaction> vtx;
        auto root = flow::consensus::compute_block_merkle_root(vtx);
        assert(root.is_null());
    }
}
