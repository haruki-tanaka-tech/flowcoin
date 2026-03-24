// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "rpc/net.h"
#include "rpc/server.h"
#include "net/net.h"
#include "net/peer.h"
#include "consensus/params.h"
#include "version.h"

#include <stdexcept>

namespace flow {

void register_net_rpcs(RpcServer& server, NetManager& net) {

    // getpeerinfo: list connected peers with detailed info
    server.register_method("getpeerinfo", [&net](const json& /*params*/) -> json {
        json result = json::array();

        auto peers = net.get_peers();
        for (const Peer* peer : peers) {
            json p;
            p["id"]              = peer->id();
            p["addr"]            = peer->addr().to_string();
            p["inbound"]         = peer->is_inbound();
            p["version"]         = peer->protocol_version();
            p["subver"]          = peer->user_agent();
            p["startingheight"]  = peer->start_height();
            p["conntime"]        = peer->connect_time();
            p["lastrecv"]        = peer->last_recv_time();
            p["lastsend"]        = peer->last_send_time();
            p["bytesrecv"]       = peer->bytes_recv();
            p["bytessent"]       = peer->bytes_sent();
            p["pingtime"]        = static_cast<double>(peer->ping_latency_us()) / 1e6;
            p["misbehavior"]     = peer->misbehavior_score();

            std::string state_str;
            switch (peer->state()) {
                case PeerState::CONNECTING:      state_str = "connecting"; break;
                case PeerState::VERSION_SENT:    state_str = "version_sent"; break;
                case PeerState::HANDSHAKE_DONE:  state_str = "connected"; break;
                case PeerState::DISCONNECTED:    state_str = "disconnected"; break;
            }
            p["state"] = state_str;

            result.push_back(p);
        }

        return result;
    });

    // getconnectioncount: number of active connections
    server.register_method("getconnectioncount", [&net](const json& /*params*/) -> json {
        return static_cast<int64_t>(net.peer_count());
    });

    // addnode(ip, command): connect to or disconnect from a peer
    // command: "add", "remove", "onetry"
    server.register_method("addnode", [&net](const json& params) -> json {
        if (params.size() < 1 || !params[0].is_string()) {
            throw std::runtime_error("Usage: addnode <ip:port> [add|remove|onetry]");
        }

        std::string addr_str = params[0].get<std::string>();
        std::string cmd = "onetry";
        if (params.size() > 1 && params[1].is_string()) {
            cmd = params[1].get<std::string>();
        }

        // Parse ip:port
        std::string ip;
        uint16_t port = consensus::MAINNET_PORT;
        auto colon = addr_str.rfind(':');
        if (colon != std::string::npos) {
            ip = addr_str.substr(0, colon);
            try {
                port = static_cast<uint16_t>(std::stoi(addr_str.substr(colon + 1)));
            } catch (...) {
                throw std::runtime_error("Invalid port number");
            }
        } else {
            ip = addr_str;
        }

        if (cmd == "add" || cmd == "onetry") {
            if (!net.add_node(ip, port)) {
                throw std::runtime_error("Failed to add node");
            }
            return true;
        } else if (cmd == "remove") {
            // Find and disconnect the peer
            auto peers = net.get_peers();
            for (Peer* peer : peers) {
                if (peer->addr().to_string().find(ip) != std::string::npos) {
                    net.disconnect(*peer, "removed via RPC");
                    return true;
                }
            }
            throw std::runtime_error("Node not found");
        }

        throw std::runtime_error("Unknown command: " + cmd);
    });

    // getnetworkinfo: general network information
    server.register_method("getnetworkinfo", [&net](const json& /*params*/) -> json {
        json j;
        j["version"]           = CLIENT_VERSION_STRING;
        j["protocolversion"]   = consensus::PROTOCOL_VERSION;
        j["connections"]       = static_cast<int64_t>(net.peer_count());
        j["connections_in"]    = static_cast<int64_t>(net.inbound_count());
        j["connections_out"]   = static_cast<int64_t>(net.outbound_count());
        j["localaddresses"]    = json::array();
        j["warnings"]          = "";

        json networks = json::array();
        json ipv4;
        ipv4["name"]       = "ipv4";
        ipv4["limited"]    = false;
        ipv4["reachable"]  = true;
        ipv4["port"]       = net.port();
        networks.push_back(ipv4);
        j["networks"] = networks;

        return j;
    });
}

} // namespace flow
