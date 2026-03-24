// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Message handler / dispatcher for the FlowCoin P2P network.
// Receives parsed messages from NetManager, dispatches to the appropriate
// handler based on command string, and sends responses back through the
// network manager.

#ifndef FLOWCOIN_NET_MESSAGES_H
#define FLOWCOIN_NET_MESSAGES_H

#include "net/protocol.h"
#include "net/peer.h"
#include "primitives/block.h"
#include "primitives/transaction.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace flow {

class ChainState;
class Mempool;
class NetManager;
struct CBlockIndex;

class MessageHandler {
public:
    MessageHandler(ChainState& chain, NetManager& netman);

    // Process a received message from a peer.
    // Parses the command, dispatches to the appropriate handler.
    void process_message(Peer& peer, const std::string& command,
                         const uint8_t* payload, size_t payload_len);

    // Send our version message to a peer (called by NetManager on outbound connect)
    void send_version(Peer& peer);

private:
    ChainState& chain_;
    NetManager& netman_;

    // Individual message handlers
    void handle_version(Peer& peer, const uint8_t* data, size_t len);
    void handle_verack(Peer& peer);
    void handle_ping(Peer& peer, const uint8_t* data, size_t len);
    void handle_pong(Peer& peer, const uint8_t* data, size_t len);
    void handle_getaddr(Peer& peer);
    void handle_addr(Peer& peer, const uint8_t* data, size_t len);
    void handle_inv(Peer& peer, const uint8_t* data, size_t len);
    void handle_getdata(Peer& peer, const uint8_t* data, size_t len);
    void handle_block(Peer& peer, const uint8_t* data, size_t len);
    void handle_tx(Peer& peer, const uint8_t* data, size_t len);
    void handle_getblocks(Peer& peer, const uint8_t* data, size_t len);
    void handle_getheaders(Peer& peer, const uint8_t* data, size_t len);
    void handle_headers(Peer& peer, const uint8_t* data, size_t len);
    void handle_reject(Peer& peer, const uint8_t* data, size_t len);
    void handle_sendheaders(Peer& peer);
    void handle_sendcmpct(Peer& peer, const uint8_t* data, size_t len);
    void handle_cmpctblock(Peer& peer, const uint8_t* data, size_t len);
    void handle_getblocktxn(Peer& peer, const uint8_t* data, size_t len);
    void handle_blocktxn(Peer& peer, const uint8_t* data, size_t len);
    void handle_feefilter(Peer& peer, const uint8_t* data, size_t len);

    // Compact block reconstruction state per peer
    struct CompactBlockState {
        uint256 block_hash;
        CBlockHeader header;
        std::vector<uint64_t> short_txids;  // 6-byte short IDs
        std::vector<CTransaction> prefilled_txs;
        std::vector<uint32_t> prefilled_indices;
        std::vector<CTransaction> reconstructed_txs;
        bool waiting_for_txns = false;
    };
    std::map<uint64_t, CompactBlockState> compact_states_;  // peer_id -> state

    // Orphan transaction pool
    struct OrphanEntry {
        CTransaction tx;
        uint64_t from_peer;
        int64_t time_added;
    };
    std::map<uint256, OrphanEntry> orphan_pool_;
    std::map<uint256, std::set<uint256>> orphan_by_parent_;  // parent_txid -> set<orphan_txid>

    // Self-address advertisement timing
    int64_t last_self_advertise_time_ = 0;

    // Compute short txid for compact blocks (first 6 bytes of siphash)
    static uint64_t compute_short_txid(const uint256& txid,
                                        uint64_t nonce,
                                        const uint256& block_hash);

    // Send a message to a peer (with payload)
    void send(Peer& peer, const std::string& command,
              const std::vector<uint8_t>& payload);

    // Send a message to a peer (empty payload)
    void send(Peer& peer, const std::string& command);

    // Announce a new block to all connected peers via INV
    void relay_block(const uint256& hash);

    // Announce a new transaction to all connected peers via INV
    void relay_tx(const uint256& txid);

    // Serialize a single InvItem into a DataWriter
    static void write_inv_item(DataWriter& w, const InvItem& item);

    // Deserialize inventory items from a payload
    static std::vector<InvItem> read_inv_items(const uint8_t* data, size_t len);

    // Serialize a block header for the headers message
    static void write_block_header(DataWriter& w, const CBlockHeader& hdr);

    // Find the fork point from a set of locator hashes
    CBlockIndex* find_fork_point(const std::vector<uint256>& locator_hashes);

    // --- Full transaction relay (extended) ---

    // Full tx handler with mempool/orphan integration
    void handle_tx_full(Peer& peer, const uint8_t* data, size_t len);

    // Full inv handler with mempool awareness
    void handle_inv_full(Peer& peer, const uint8_t* data, size_t len);

    // Full getdata handler serving txs from mempool
    void handle_getdata_full(Peer& peer, const uint8_t* data, size_t len);

    // Notfound response handler
    void handle_notfound_full(Peer& peer, const uint8_t* data, size_t len);

    // Orphan pool management
    void add_orphan_tx(const CTransaction& tx, uint64_t from_peer);
    void evict_random_orphan();
    void process_orphan_dependents(const uint256& parent_txid);
    void expire_orphans();

    // Transaction relay to peers (respecting fee filter)
    void relay_tx_to_peers(const uint256& txid, uint64_t except_peer);

    // Trickle: batch-send pending INV announcements
    void send_inv_trickle();

    // Block relay with announcement mode selection
    void relay_block_full(const CBlock& block);
    void send_compact_block(Peer& peer, const CBlock& block);
    void relay_transaction_full(const CTransaction& tx);

    // Address relay with probability-based forwarding
    void handle_addr_full(Peer& peer, const uint8_t* data, size_t len);
    void relay_addresses(const std::vector<CNetAddr>& addrs, uint64_t except_peer);
    void handle_getaddr_full(Peer& peer);
    void advertise_local_address();

    // Ping/pong with full latency tracking
    void send_ping(Peer& peer);
    void handle_ping_full(Peer& peer, const uint8_t* data, size_t len);
    void handle_pong_full(Peer& peer, const uint8_t* data, size_t len);

    // Send a reject message to a peer
    void send_reject(Peer& peer, const std::string& rejected_cmd,
                     uint8_t code, const std::string& reason,
                     const uint256& hash = uint256());

public:
    // Periodic maintenance (called from NetManager tick)
    void on_tick();
};

} // namespace flow

#endif // FLOWCOIN_NET_MESSAGES_H
