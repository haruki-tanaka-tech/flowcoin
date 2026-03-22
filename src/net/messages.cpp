// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "messages.h"
#include "core/time.h"

#include <spdlog/spdlog.h>

namespace flow::net {

MessageHandler::MessageHandler(NetManager& net, ChainState& chain, Mempool& mempool)
    : net_(net), chain_(chain), mempool_(mempool) {}

void MessageHandler::handle(uint64_t peer_id, const std::string& command,
                             const std::vector<uint8_t>& payload) {
    if (command == cmd::VERSION)        handle_version(peer_id, payload);
    else if (command == cmd::VERACK)    handle_verack(peer_id);
    else if (command == cmd::PING)      handle_ping(peer_id, payload);
    else if (command == cmd::PONG)      handle_pong(peer_id, payload);
    else if (command == cmd::GETBLOCKS) handle_getblocks(peer_id, payload);
    else if (command == cmd::INV)       handle_inv(peer_id, payload);
    else if (command == cmd::GETDATA)   handle_getdata(peer_id, payload);
    else if (command == cmd::BLOCK)     handle_block(peer_id, payload);
    else if (command == cmd::TX)        handle_tx(peer_id, payload);
    else {
        spdlog::debug("P2P unknown command '{}' from peer {}", command, peer_id);
    }
}

void MessageHandler::on_peer_connected(uint64_t peer_id) {
    send_version(peer_id);
}

void MessageHandler::on_peer_disconnected(uint64_t peer_id) {
    spdlog::debug("P2P peer {} disconnected", peer_id);
}

void MessageHandler::send_version(uint64_t peer_id) {
    VersionMessage ver;
    ver.protocol_version = consensus::PROTOCOL_VERSION;
    ver.best_height = chain_.tip() ? chain_.tip()->height : 0;
    ver.timestamp = get_time();

    net_.send_to(peer_id, cmd::VERSION, ver.serialize());
}

void MessageHandler::handle_version(uint64_t peer_id, const std::vector<uint8_t>& payload) {
    if (payload.size() < 20) return;

    auto ver = VersionMessage::deserialize(payload.data(), payload.size());

    spdlog::info("P2P recv version from peer {}: v={}, height={}",
        peer_id, ver.protocol_version, ver.best_height);

    // Update peer with version info
    net_.update_peer(peer_id, [&](Peer& peer) {
        peer.info().protocol_version = ver.protocol_version;
        peer.info().best_height = ver.best_height;
        peer.set_state(PeerState::VERSION_SENT);
    });

    // Send verack
    net_.send_to(peer_id, cmd::VERACK, {});

    // If inbound peer, also send our version
    bool is_inbound = false;
    auto peers = net_.get_peer_info();
    for (const auto& p : peers) {
        if (p.id == peer_id) { is_inbound = p.inbound; break; }
    }
    if (is_inbound) {
        send_version(peer_id);
    }
}

void MessageHandler::handle_verack(uint64_t peer_id) {
    net_.update_peer(peer_id, [](Peer& peer) {
        peer.set_state(PeerState::ESTABLISHED);
    });

    spdlog::info("P2P handshake complete with peer {}", peer_id);

    // Check if peer has blocks we need
    uint64_t our_height = chain_.tip() ? chain_.tip()->height : 0;
    uint64_t their_height = 0;

    auto peers = net_.get_peer_info();
    for (const auto& p : peers) {
        if (p.id == peer_id) { their_height = p.best_height; break; }
    }

    if (their_height > our_height) {
        // Request blocks — send getblocks with our height
        VectorWriter w;
        w.write_u64(our_height);
        net_.send_to(peer_id, cmd::GETBLOCKS, w.release());
        spdlog::info("P2P requesting blocks from {} (we have {}, they have {})",
            peer_id, our_height, their_height);
    }
}

void MessageHandler::handle_ping(uint64_t peer_id, const std::vector<uint8_t>& payload) {
    net_.send_to(peer_id, cmd::PONG, payload);
}

void MessageHandler::handle_pong(uint64_t, const std::vector<uint8_t>&) {}

void MessageHandler::handle_getblocks(uint64_t peer_id, const std::vector<uint8_t>& payload) {
    if (payload.size() < 8) return;

    SpanReader reader(payload);
    uint64_t from_height = reader.read_u64();

    // Send inv for blocks above from_height
    auto chain_vec = chain_.block_tree().get_chain(chain_.tip());
    VectorWriter inv_data;
    uint64_t count = 0;

    for (const auto* idx : chain_vec) {
        if (idx->height > from_height && count < 500) {
            inv_data.write_u32(static_cast<uint32_t>(InvType::BLOCK));
            inv_data.write_bytes(std::span<const uint8_t>(idx->hash.bytes(), 32));
            count++;
        }
    }

    if (count > 0) {
        VectorWriter msg;
        msg.write_compact_size(count);
        auto data = inv_data.release();
        msg.write_bytes(data);
        net_.send_to(peer_id, cmd::INV, msg.release());
        spdlog::info("P2P sent {} inv items to peer {}", count, peer_id);
    }
}

void MessageHandler::handle_inv(uint64_t peer_id, const std::vector<uint8_t>& payload) {
    SpanReader reader(payload);
    uint64_t count = reader.read_compact_size();

    VectorWriter getdata;
    uint64_t request_count = 0;

    for (uint64_t i = 0; i < count && !reader.empty(); ++i) {
        uint32_t type = reader.read_u32();
        Hash256 hash;
        reader.read_bytes(hash.bytes(), 32);

        if (static_cast<InvType>(type) == InvType::BLOCK) {
            if (!chain_.block_tree().find(hash)) {
                getdata.write_u32(type);
                getdata.write_bytes(std::span<const uint8_t>(hash.bytes(), 32));
                request_count++;
            }
        }
    }

    if (request_count > 0) {
        VectorWriter msg;
        msg.write_compact_size(request_count);
        auto data = getdata.release();
        msg.write_bytes(data);
        net_.send_to(peer_id, cmd::GETDATA, msg.release());
        spdlog::info("P2P requesting {} blocks from peer {}", request_count, peer_id);
    }
}

void MessageHandler::handle_getdata(uint64_t peer_id, const std::vector<uint8_t>& payload) {
    SpanReader reader(payload);
    uint64_t count = reader.read_compact_size();

    for (uint64_t i = 0; i < count && !reader.empty(); ++i) {
        uint32_t type = reader.read_u32();
        Hash256 hash;
        reader.read_bytes(hash.bytes(), 32);

        if (static_cast<InvType>(type) == InvType::BLOCK) {
            auto block_data = chain_.get_block_data(hash);
            if (!block_data.empty()) {
                net_.send_to(peer_id, cmd::BLOCK, block_data);
                spdlog::info("P2P sent block {} to peer {} ({} bytes)",
                    hash.to_hex().substr(0, 16), peer_id, block_data.size());
            }
        }
    }
}

void MessageHandler::handle_block(uint64_t peer_id, const std::vector<uint8_t>& payload) {
    try {
        CBlock block = CBlock::deserialize(payload);
        spdlog::info("P2P received block height={} from peer {} ({} bytes)",
            block.header.height, peer_id, payload.size());

        auto state = chain_.accept_block(block);
        if (state.valid) {
            spdlog::info("P2P accepted block {} hash={}",
                block.header.height, block.get_hash().to_hex().substr(0, 16));

            // Relay to other peers
            VectorWriter inv_msg;
            inv_msg.write_compact_size(1);
            inv_msg.write_u32(static_cast<uint32_t>(InvType::BLOCK));
            inv_msg.write_bytes(std::span<const uint8_t>(block.get_hash().bytes(), 32));
            net_.broadcast(cmd::INV, inv_msg.release());
        } else {
            spdlog::warn("P2P rejected block from peer {}: {}", peer_id, state.reject_reason);
        }
    } catch (const std::exception& e) {
        spdlog::warn("P2P bad block from peer {}: {}", peer_id, e.what());
    }
}

void MessageHandler::handle_tx(uint64_t peer_id, const std::vector<uint8_t>& payload) {
    try {
        SpanReader reader(payload);
        CTransaction tx = CTransaction::deserialize(reader);
        auto result = mempool_.add(tx, Amount{0});
        if (result.ok()) {
            spdlog::debug("P2P accepted tx from peer {}", peer_id);
        }
    } catch (const std::exception& e) {
        spdlog::debug("P2P bad tx from peer {}: {}", peer_id, e.what());
    }
}

} // namespace flow::net
