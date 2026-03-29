// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "rpc/net.h"
#include "rpc/server.h"
#include "net/net.h"
#include "net/banman.h"
#include "net/peer.h"
#include "consensus/params.h"
#include "version.h"

#include <chrono>
#include <map>
#include <stdexcept>

namespace flow {

void register_net_rpcs(RpcServer& server, NetManager& net) {

    // -----------------------------------------------------------------------
    // getpeerinfo: detailed peer info
    // -----------------------------------------------------------------------
    server.register_method("getpeerinfo", [&net](const json& /*params*/) -> json {
        json result = json::array();
        auto peers = net.get_peers();

        // Group peers by node_id (same node via IPv4+IPv6 = one entry)
        std::map<uint64_t, std::vector<const Peer*>> grouped;
        std::vector<const Peer*> ungrouped; // node_id == 0
        for (const Peer* peer : peers) {
            uint64_t nid = peer->node_id();
            if (nid != 0) {
                grouped[nid].push_back(peer);
            } else {
                ungrouped.push_back(peer);
            }
        }

        auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        auto make_peer_json = [&](const std::vector<const Peer*>& conns) -> json {
            const Peer* primary = conns[0];
            json p;
            p["id"] = primary->id();

            // node_id hex string (FlowCoin-specific bonus)
            char nid_hex[17];
            snprintf(nid_hex, sizeof(nid_hex), "%016llx",
                     (unsigned long long)primary->node_id());
            p["node_id"] = nid_hex;

            // addr: always a single string (first address), matching Bitcoin Core
            p["addr"] = primary->addr().to_string();
            p["addrlocal"] = "";
            p["network"] = primary->addr().is_ipv4() ? "ipv4" : "ipv6";

            p["inbound"]        = primary->is_inbound();
            p["version"]        = primary->protocol_version();
            p["subver"]         = primary->user_agent();

            // services as hex string (Bitcoin Core format)
            char svc_hex[17];
            snprintf(svc_hex, sizeof(svc_hex), "%016llx",
                     (unsigned long long)primary->services());
            p["services"] = svc_hex;

            // servicesnames array
            json svc_names = json::array();
            if (primary->services() & PEER_NODE_NETWORK)
                svc_names.push_back("NETWORK");
            if (primary->services() & PEER_NODE_BLOOM)
                svc_names.push_back("BLOOM");
            if (primary->services() & PEER_NODE_COMPACT_FILTERS)
                svc_names.push_back("COMPACT_FILTERS");
            if (primary->services() & PEER_NODE_NETWORK_LIMITED)
                svc_names.push_back("NETWORK_LIMITED");
            p["servicesnames"] = svc_names;

            p["startingheight"] = primary->start_height();
            p["synced_headers"] = primary->start_height();
            p["synced_blocks"]  = primary->start_height();
            p["conntime"]       = primary->connect_time();
            p["lastrecv"]       = primary->last_recv_time();
            p["lastsend"]       = primary->last_send_time();
            p["pingtime"]       = static_cast<double>(primary->ping_latency_us()) / 1e6;
            p["minping"]        = static_cast<double>(primary->min_ping_us()) / 1e6;

            // Sum bandwidth across all connections
            uint64_t total_recv = 0, total_sent = 0;
            for (const Peer* c : conns) {
                total_recv += c->bytes_recv();
                total_sent += c->bytes_sent();
            }
            p["bytesrecv"] = total_recv;
            p["bytessent"] = total_sent;

            // FlowCoin-specific bonus fields
            p["misbehavior"]        = primary->misbehavior_score();
            p["connection_duration"] = now_secs - primary->connect_time();

            return p;
        };

        // Grouped peers (same node_id)
        for (const auto& [nid, conns] : grouped) {
            result.push_back(make_peer_json(conns));
        }

        // Ungrouped peers (no node_id)
        for (const Peer* peer : ungrouped) {
            std::vector<const Peer*> single = {peer};
            result.push_back(make_peer_json(single));
        }

        return result;
    });

    // -----------------------------------------------------------------------
    // getconnectioncount: number of active connections
    // -----------------------------------------------------------------------
    server.register_method("getconnectioncount", [&net](const json& /*params*/) -> json {
        return static_cast<int64_t>(net.peer_count());
    });

    // -----------------------------------------------------------------------
    // addnode(ip, command): connect to or disconnect from a peer
    // command: "add", "remove", "onetry"
    // -----------------------------------------------------------------------
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

    // -----------------------------------------------------------------------
    // disconnectnode(addr): disconnect a specific peer
    // -----------------------------------------------------------------------
    server.register_method("disconnectnode", [&net](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: disconnectnode <ip:port>");
        }

        std::string addr_str = params[0].get<std::string>();

        // Try to find the peer by address string
        auto peers = net.get_peers();
        for (Peer* peer : peers) {
            std::string peer_addr = peer->addr().to_string();
            if (peer_addr == addr_str ||
                peer_addr.find(addr_str) != std::string::npos) {
                net.disconnect(*peer, "disconnected via RPC");
                return true;
            }
        }

        // Try matching by peer ID if the parameter is numeric
        try {
            uint64_t peer_id = std::stoull(addr_str);
            for (Peer* peer : peers) {
                if (peer->id() == peer_id) {
                    net.disconnect(*peer, "disconnected via RPC");
                    return true;
                }
            }
        } catch (...) {
            // Not a numeric ID, fall through
        }

        throw std::runtime_error("Node not found: " + addr_str);
    });

    // -----------------------------------------------------------------------
    // getnetworkinfo: general network information
    // -----------------------------------------------------------------------
    server.register_method("getnetworkinfo", [&net](const json& /*params*/) -> json {
        json j;
        j["version"]           = flow::version::CLIENT_VERSION;
        j["subversion"]        = flow::version::USER_AGENT;
        j["protocolversion"]   = consensus::PROTOCOL_VERSION;
        j["localservices"]     = "0000000000000001";
        j["localservicesnames"] = json::array({"NETWORK"});
        j["localrelay"]        = true;
        j["networkactive"]     = true;
        j["connections"]       = static_cast<int64_t>(net.peer_count());
        j["connections_in"]    = static_cast<int64_t>(net.inbound_count());
        j["connections_out"]   = static_cast<int64_t>(net.outbound_count());
        j["localaddresses"]    = json::array();
        j["warnings"]          = "";

        // Network interfaces
        json networks = json::array();
        {
            json ipv4;
            ipv4["name"]       = "ipv4";
            ipv4["limited"]    = false;
            ipv4["reachable"]  = true;
            ipv4["port"]       = net.port();
            networks.push_back(ipv4);
        }
        j["networks"] = networks;

        // Relay fee info
        double min_relay_fee = 1000.0 / static_cast<double>(consensus::COIN);
        j["relayfee"]     = min_relay_fee;
        j["incrementalfee"] = min_relay_fee;

        // Network time offset (we don't adjust time, so 0)
        j["timeoffset"] = 0;

        return j;
    });

    // -----------------------------------------------------------------------
    // getnettotals: total bytes sent/received and uptime
    // -----------------------------------------------------------------------
    server.register_method("getnettotals", [&net](const json& /*params*/) -> json {
        json j;
        j["totalbytesrecv"] = net.total_bytes_recv();
        j["totalbytessent"] = net.total_bytes_sent();

        // Time since server start (approximate from connection times)
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        j["timemillis"] = now * 1000;

        // Upload/download target (no limit by default)
        json upload_target;
        upload_target["timeframe"]   = 86400;
        upload_target["target"]      = 0;
        upload_target["target_reached"] = false;
        upload_target["serve_historical_blocks"] = true;
        upload_target["bytes_left_in_cycle"] = 0;
        upload_target["time_left_in_cycle"]  = 0;
        j["uploadtarget"] = upload_target;

        return j;
    });

    // -----------------------------------------------------------------------
    // listbanned: list all banned IPs
    // -----------------------------------------------------------------------
    server.register_method("listbanned", [&net](const json& /*params*/) -> json {
        json result = json::array();

        auto banned = net.banman().list_banned();
        for (const auto& entry : banned) {
            json ban;
            ban["address"]     = entry.addr_string;
            ban["ban_created"] = entry.ban_created;
            ban["banned_until"] = entry.ban_until;

            // Calculate remaining ban time
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            int64_t remaining = entry.ban_until - now;
            ban["ban_remaining"] = (remaining > 0) ? remaining : 0;
            ban["ban_reason"]    = "manually set via RPC or misbehavior";

            result.push_back(ban);
        }

        return result;
    });

    // -----------------------------------------------------------------------
    // setban(addr, command, duration): ban or unban a peer
    // -----------------------------------------------------------------------
    server.register_method("setban", [&net](const json& params) -> json {
        if (params.size() < 2 || !params[0].is_string() || !params[1].is_string()) {
            throw std::runtime_error("Usage: setban <ip> <add|remove> [duration_seconds]");
        }

        std::string addr_str = params[0].get<std::string>();
        std::string command = params[1].get<std::string>();

        // Parse IP (strip port if present)
        std::string ip = addr_str;
        auto colon = addr_str.rfind(':');
        if (colon != std::string::npos) {
            ip = addr_str.substr(0, colon);
        }

        if (command == "add") {
            int64_t duration = BanMan::DEFAULT_BAN_DURATION;
            if (params.size() > 2 && params[2].is_number()) {
                duration = params[2].get<int64_t>();
                if (duration <= 0) duration = BanMan::DEFAULT_BAN_DURATION;
            }

            // Create a CNetAddr and ban it
            CNetAddr ban_addr;
            ban_addr = CNetAddr(ip, 0); // port doesn't matter for banning
            net.banman().ban(ban_addr, duration);

            // Also disconnect the peer if currently connected
            auto peers = net.get_peers();
            for (Peer* peer : peers) {
                if (peer->addr().to_string().find(ip) != std::string::npos) {
                    net.disconnect(*peer, "banned via RPC");
                }
            }

            return true;
        } else if (command == "remove") {
            CNetAddr unban_addr;
            unban_addr = CNetAddr(ip, 0);
            net.banman().unban(unban_addr);
            return true;
        }

        throw std::runtime_error("Invalid command '" + command + "'. Use 'add' or 'remove'.");
    });

    // -----------------------------------------------------------------------
    // clearbanned: remove all banned IPs
    // -----------------------------------------------------------------------
    server.register_method("clearbanned", [&net](const json& /*params*/) -> json {
        net.banman().clear();
        return true;
    });

    // -----------------------------------------------------------------------
    // ping: request ping from all peers
    // -----------------------------------------------------------------------
    server.register_method("ping", [&net](const json& /*params*/) -> json {
        // Send a ping message to all connected peers
        // The ping responses will be tracked by the P2P layer
        std::vector<uint8_t> empty_payload;
        net.broadcast("ping", empty_payload);
        return nullptr; // null = success
    });

    // -----------------------------------------------------------------------
    // getaddednodeinfo: info about manually added nodes
    // -----------------------------------------------------------------------
    server.register_method("getaddednodeinfo", [&net](const json& params) -> json {
        json result = json::array();

        // Optional filter by address
        std::string filter;
        if (!params.empty() && params[0].is_string()) {
            filter = params[0].get<std::string>();
        }

        auto peers = net.get_peers();
        for (const Peer* peer : peers) {
            std::string peer_addr = peer->addr().to_string();

            if (!filter.empty() && peer_addr.find(filter) == std::string::npos) {
                continue;
            }

            json node;
            node["addednode"] = peer_addr;
            node["connected"] = (peer->state() == PeerState::HANDSHAKE_DONE);

            json addresses = json::array();
            json addr_entry;
            addr_entry["address"]   = peer_addr;
            addr_entry["connected"] = peer->is_inbound() ? "inbound" : "outbound";
            addresses.push_back(addr_entry);
            node["addresses"] = addresses;

            result.push_back(node);
        }

        return result;
    });

    // -----------------------------------------------------------------------
    // getpeercount: alias for getconnectioncount (common in some clients)
    // -----------------------------------------------------------------------
    server.register_method("getpeercount", [&net](const json& /*params*/) -> json {
        return static_cast<int64_t>(net.peer_count());
    });

    // -----------------------------------------------------------------------
    // getnodeaddresses: return known addresses from the address manager
    // -----------------------------------------------------------------------
    server.register_method("getnodeaddresses", [&net](const json& params) -> json {
        int count = 10;
        if (!params.empty() && params[0].is_number_integer()) {
            count = params[0].get<int>();
            if (count <= 0) count = 1;
            if (count > 2500) count = 2500;
        }

        json result = json::array();

        // Return info from connected peers as known addresses
        auto peers = net.get_peers();
        int returned = 0;
        for (const Peer* peer : peers) {
            if (returned >= count) break;
            if (peer->state() != PeerState::HANDSHAKE_DONE) continue;

            json addr;
            CNetAddr peer_listen = peer->addr();
            if (peer->listen_port() != 0) {
                peer_listen.port = peer->listen_port();
            }
            addr["address"]  = peer_listen.to_string();
            addr["port"]     = peer->listen_port() != 0 ? peer->listen_port() : peer->addr().port;
            addr["services"] = peer->services();
            addr["time"]     = peer->connect_time();
            result.push_back(addr);
            returned++;
        }

        return result;
    });
}

} // namespace flow
