// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// P2P message handler: processes incoming messages and generates responses.
// Handles the version/verack handshake, block/tx relay, and IBD.

#pragma once

#include "netman.h"
#include "chain/chainstate.h"
#include "mempool/mempool.h"

namespace flow::net {

class MessageHandler {
public:
    MessageHandler(NetManager& net, ChainState& chain, Mempool& mempool);

    // Process an incoming message from a peer.
    // Called by NetManager's on_message callback.
    void handle(uint64_t peer_id, const std::string& command,
                const std::vector<uint8_t>& payload);

    // Called when a peer connects — initiate handshake.
    void on_peer_connected(uint64_t peer_id);

    // Called when a peer disconnects.
    void on_peer_disconnected(uint64_t peer_id);

private:
    NetManager& net_;
    ChainState& chain_;
    Mempool& mempool_;

    void handle_version(uint64_t peer_id, const std::vector<uint8_t>& payload);
    void handle_verack(uint64_t peer_id);
    void handle_ping(uint64_t peer_id, const std::vector<uint8_t>& payload);
    void handle_pong(uint64_t peer_id, const std::vector<uint8_t>& payload);
    void handle_getblocks(uint64_t peer_id, const std::vector<uint8_t>& payload);
    void handle_inv(uint64_t peer_id, const std::vector<uint8_t>& payload);
    void handle_getdata(uint64_t peer_id, const std::vector<uint8_t>& payload);
    void handle_block(uint64_t peer_id, const std::vector<uint8_t>& payload);
    void handle_tx(uint64_t peer_id, const std::vector<uint8_t>& payload);

    // Send version message to initiate handshake
    void send_version(uint64_t peer_id);
};

} // namespace flow::net
