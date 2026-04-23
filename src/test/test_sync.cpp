// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for sync-related logic: block locator construction and
// peer state tracking.

#include "chain/blockindex.h"
#include "consensus/params.h"
#include "hash/keccak.h"
#include "net/peer.h"
#include "net/protocol.h"
#include "primitives/block.h"
#include "util/types.h"
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <vector>

// Helper: create a simple block header with a given height and prev_hash
static flow::CBlockHeader make_header(uint64_t height, const flow::uint256& prev) {
    flow::CBlockHeader hdr;
    hdr.height = height;
    hdr.prev_hash = prev;
    hdr.timestamp = flow::consensus::GENESIS_TIMESTAMP + (int64_t)height * 600;
    hdr.nbits = flow::consensus::INITIAL_NBITS;
    hdr.version = 1;
    return hdr;
}

void test_sync() {
    using namespace flow;
    using namespace flow::consensus;

    // Test 1: Build locator from a short chain (fewer than 10 blocks)
    {
        BlockTree tree;

        // Create genesis
        auto genesis_hdr = make_header(0, uint256());
        auto* genesis = tree.insert(genesis_hdr);
        tree.set_best_tip(genesis);

        // Build a chain of 5 blocks
        CBlockIndex* prev = genesis;
        for (uint64_t h = 1; h <= 5; h++) {
            auto hdr = make_header(h, prev->hash);
            auto* idx = tree.insert(hdr);
            idx->prev = prev;
            prev = idx;
        }
        tree.set_best_tip(prev);

        auto locator = flow::build_locator(tree.best_tip());

        // For a 6-block chain (0-5), locator should have all 6 hashes
        // (all within the first 10 single-step entries)
        assert(locator.hashes.size() == 6);

        // First entry should be the tip
        assert(locator.hashes[0] == prev->hash);
    }

    // Test 2: Build locator from a long chain (more than 10 blocks)
    {
        BlockTree tree;

        auto genesis_hdr = make_header(0, uint256());
        auto* genesis = tree.insert(genesis_hdr);
        tree.set_best_tip(genesis);

        // Build a chain of 100 blocks
        CBlockIndex* prev = genesis;
        for (uint64_t h = 1; h <= 100; h++) {
            auto hdr = make_header(h, prev->hash);
            auto* idx = tree.insert(hdr);
            idx->prev = prev;
            prev = idx;
        }
        tree.set_best_tip(prev);

        auto locator = flow::build_locator(tree.best_tip());

        // Locator should have entries:
        // - First 10 or 11 hashes are single-step
        // - Then entries double (2, 4, 8, 16, ...)
        // Total should be significantly less than 101
        assert(locator.hashes.size() < 30);
        assert(locator.hashes.size() > 10);

        // First entry is the tip (height 100)
        assert(locator.hashes[0] == prev->hash);
    }

    // Test 3: Peer state transitions
    {
        CNetAddr addr("127.0.0.1", 9333);
        Peer peer(1, addr, false);

        // Initial state
        assert(peer.state() == PeerState::CONNECTING);
        assert(!peer.version_received());
        assert(!peer.verack_received());
        assert(!peer.version_sent());

        // Transition: CONNECTING -> VERSION_SENT
        peer.set_state(PeerState::VERSION_SENT);
        peer.set_version_sent(true);
        assert(peer.state() == PeerState::VERSION_SENT);
        assert(peer.version_sent());

        // Receive version from remote
        peer.set_version_received(true);
        peer.set_version(PROTOCOL_VERSION);
        peer.set_start_height(50);
        peer.set_user_agent("/FlowCoin:0.1.0/");
        assert(peer.version_received());
        assert(peer.protocol_version() == PROTOCOL_VERSION);
        assert(peer.start_height() == 50);

        // Receive verack -> HANDSHAKE_DONE
        peer.set_verack_received(true);
        peer.set_state(PeerState::HANDSHAKE_DONE);
        assert(peer.state() == PeerState::HANDSHAKE_DONE);
        assert(peer.verack_received());

        // Disconnect
        peer.set_state(PeerState::DISCONNECTED);
        assert(peer.state() == PeerState::DISCONNECTED);
    }

    // Test 4: Peer misbehavior tracking
    {
        CNetAddr addr("127.0.0.1", 9333);
        Peer peer(2, addr, true);

        assert(peer.misbehavior_score() == 0);
        assert(!peer.should_ban());

        peer.add_misbehavior(10);
        assert(peer.misbehavior_score() == 10);
        assert(!peer.should_ban());

        peer.add_misbehavior(50);
        assert(peer.misbehavior_score() == 60);
        assert(!peer.should_ban());

        peer.add_misbehavior(40);
        assert(peer.misbehavior_score() == 100);
        assert(peer.should_ban());
    }

    // Test 5: Peer counters
    {
        CNetAddr addr("192.168.1.1", 9333);
        Peer peer(3, addr, false);

        assert(peer.messages_recv() == 0);
        assert(peer.messages_sent() == 0);
        assert(peer.bytes_recv() == 0);
        assert(peer.bytes_sent() == 0);

        peer.inc_messages_recv();
        peer.inc_messages_recv();
        peer.inc_messages_sent();
        peer.add_bytes_recv(1024);
        peer.add_bytes_sent(512);

        assert(peer.messages_recv() == 2);
        assert(peer.messages_sent() == 1);
        assert(peer.bytes_recv() == 1024);
        assert(peer.bytes_sent() == 512);
    }

    // Test 6: Inbound vs outbound peer
    {
        CNetAddr addr1("10.0.0.1", 9333);
        Peer inbound(4, addr1, true);
        assert(inbound.is_inbound());

        CNetAddr addr2("10.0.0.2", 9333);
        Peer outbound(5, addr2, false);
        assert(!outbound.is_inbound());
    }

    // Test 7: BlockTree lookup
    {
        BlockTree tree;

        auto genesis_hdr = make_header(0, uint256());
        auto* genesis = tree.insert(genesis_hdr);

        // Find by hash should work
        auto* found = tree.find(genesis->hash);
        assert(found == genesis);

        // Unknown hash returns nullptr
        uint256 unknown;
        unknown.set_null();
        unknown[0] = 0xFF;
        assert(tree.find(unknown) == nullptr);

        // Inserting duplicate returns existing
        auto* dup = tree.insert(genesis_hdr);
        assert(dup == genesis);
        assert(tree.size() == 1);
    }
}
