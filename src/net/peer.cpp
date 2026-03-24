// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "net/peer.h"
#include "util/time.h"

namespace flow {

Peer::Peer(uint64_t id, const CNetAddr& addr, bool inbound)
    : id_(id)
    , addr_(addr)
    , inbound_(inbound)
    , state_(PeerState::CONNECTING)
    , start_height_(0)
    , protocol_version_(0)
    , nonce_(0)
    , services_(0)
    , last_ping_time_(0)
    , ping_nonce_(0)
    , ping_latency_us_(0)
    , misbehavior_(0)
    , connect_time_(GetTime())
    , last_recv_time_(0)
    , last_send_time_(0)
    , version_received_(false)
    , verack_received_(false)
    , version_sent_(false)
    , tcp_handle_(nullptr)
    , messages_recv_(0)
    , messages_sent_(0)
    , bytes_recv_(0)
    , bytes_sent_(0)
{
    recv_buf_.reserve(4096);
}

} // namespace flow
