// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Network utilities: DNS lookup, socket operations, proxy support.
// Provides low-level network functions used by NetManager for connection
// establishment, address resolution, and socket configuration.

#ifndef FLOWCOIN_NET_NETBASE_H
#define FLOWCOIN_NET_NETBASE_H

#include "net/netaddress.h"

#include <cstdint>
#include <string>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// DNS and address resolution
// ---------------------------------------------------------------------------

// Resolve a hostname to a list of IP addresses using getaddrinfo().
// Returns empty vector on failure. Supports both IPv4 and IPv6 results.
// If allow_lookup is false, only numeric IP addresses are accepted.
std::vector<CNetAddr2> LookupHost(const std::string& name,
                                   unsigned int max_results = 0,
                                   bool allow_lookup = true);

// Parse a numeric IP string (no DNS lookup). Returns false if not a valid IP.
bool LookupNumeric(const std::string& ip_string, CNetAddr2& out);

// Resolve a hostname:port to a list of CService endpoints.
// If the string does not contain a port, default_port is used.
std::vector<CService> LookupService(const std::string& name,
                                     uint16_t default_port,
                                     unsigned int max_results = 0,
                                     bool allow_lookup = true);

// Resolve a single hostname:port. Returns false if resolution fails.
bool LookupServiceSingle(const std::string& name,
                          uint16_t default_port,
                          CService& out,
                          bool allow_lookup = true);

// ---------------------------------------------------------------------------
// Socket operations
// ---------------------------------------------------------------------------

// Create a TCP socket and connect to the given address with a timeout.
// Returns the socket file descriptor on success, or -1 on failure.
// The socket is left in blocking mode after connection.
int ConnectSocket(const CService& addr, int timeout_ms = 5000);

// Set a socket to non-blocking mode. Returns true on success.
bool SetSocketNonBlocking(int fd);

// Set TCP_NODELAY on a socket (disable Nagle's algorithm). Returns true on success.
bool SetSocketNoDelay(int fd);

// Set SO_REUSEADDR on a socket. Returns true on success.
bool SetSocketReuseAddr(int fd);

// Set SO_KEEPALIVE on a socket. Returns true on success.
bool SetSocketKeepAlive(int fd);

// Close a socket file descriptor.
void CloseSocket(int fd);

// Get the local address of a connected socket.
bool GetSocketLocalAddr(int fd, CService& out);

// Get the remote address of a connected socket.
bool GetSocketPeerAddr(int fd, CService& out);

// ---------------------------------------------------------------------------
// Local address detection
// ---------------------------------------------------------------------------

// Detect our external IP address by examining local network interfaces.
// Returns a best-guess routable address, or an empty CNetAddr2 if none found.
CNetAddr2 GetLocalAddress();

// Detect the local address we would use to reach a specific target.
// Connects a UDP socket and checks the local side. More reliable than
// GetLocalAddress() when we have a specific peer to reach.
CNetAddr2 GetLocalAddressForPeer(const CNetAddr2& peer);

// Check if a network is reachable (not explicitly blocked).
bool IsReachable(Network net);
bool IsReachable(const CNetAddr2& addr);

// Set whether a network is reachable. Used to disable IPv4 or IPv6.
void SetReachable(Network net, bool reachable);

// ---------------------------------------------------------------------------
// Proxy support (SOCKS5)
// ---------------------------------------------------------------------------

struct ProxyConfig {
    CService proxy;
    bool randomize_credentials = false;

    ProxyConfig() = default;
    ProxyConfig(const CService& p, bool rand_creds = false)
        : proxy(p), randomize_credentials(rand_creds) {}

    bool IsValid() const { return proxy.GetPort() != 0; }
};

// Set the proxy for a given network type.
void SetProxy(Network net, const ProxyConfig& config);

// Get the proxy for a given network type. Returns false if no proxy is set.
bool GetProxy(Network net, ProxyConfig& config);

// Set the name proxy (for hostname resolution via proxy, e.g., Tor).
void SetNameProxy(const ProxyConfig& config);

// Get the name proxy.
bool GetNameProxy(ProxyConfig& config);

// Check if any proxy is set for the given network.
bool HasProxy(Network net);

// Connect through a SOCKS5 proxy. Returns the connected socket fd, or -1.
// The target_host can be a hostname (resolved by the proxy).
int ConnectThroughProxy(const ProxyConfig& proxy,
                         const std::string& target_host,
                         uint16_t target_port,
                         int timeout_ms = 5000);

// ---------------------------------------------------------------------------
// Miscellaneous
// ---------------------------------------------------------------------------

// Split a host:port string into components. Returns false on parse error.
bool SplitHostPort(const std::string& str, std::string& host, uint16_t& port);

// Validate that a hostname or IP string looks reasonable (no embedded nulls, etc.).
bool ValidateHostString(const std::string& str);

} // namespace flow

#endif // FLOWCOIN_NET_NETBASE_H
