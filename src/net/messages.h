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
#include <string>
#include <vector>

namespace flow {

class ChainState;
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
};

} // namespace flow

#endif // FLOWCOIN_NET_MESSAGES_H
