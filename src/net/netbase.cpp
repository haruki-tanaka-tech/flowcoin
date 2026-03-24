// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Network utilities implementation: DNS lookup, socket operations, proxy.

#include "net/netbase.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <ifaddrs.h>
#include <mutex>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace flow {

// ===========================================================================
// Global state for network reachability and proxy settings
// ===========================================================================

static std::mutex g_netbase_mutex;
static bool g_reachable[NET_MAX] = { true, true, true, true, true };
static ProxyConfig g_proxy[NET_MAX];
static ProxyConfig g_name_proxy;
static bool g_name_proxy_set = false;

// ===========================================================================
// DNS resolution
// ===========================================================================

std::vector<CNetAddr2> LookupHost(const std::string& name,
                                   unsigned int max_results,
                                   bool allow_lookup) {
    std::vector<CNetAddr2> result;

    if (name.empty()) return result;

    // First try as a numeric IP
    CNetAddr2 numeric;
    if (CNetAddr2::ParseIP(name, numeric)) {
        result.push_back(numeric);
        return result;
    }

    // If lookup is not allowed, return empty
    if (!allow_lookup) return result;

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG;

    struct addrinfo* ai_result = nullptr;
    int err = getaddrinfo(name.c_str(), nullptr, &hints, &ai_result);
    if (err != 0) {
        return result;
    }

    for (struct addrinfo* ai = ai_result; ai != nullptr; ai = ai->ai_next) {
        if (max_results > 0 && result.size() >= max_results) break;

        CNetAddr2 addr;
        if (ai->ai_family == AF_INET) {
            auto* sin = reinterpret_cast<struct sockaddr_in*>(ai->ai_addr);
            uint32_t ipv4;
            std::memcpy(&ipv4, &sin->sin_addr.s_addr, 4);
            addr.SetIPv4(ipv4);
            result.push_back(addr);
        } else if (ai->ai_family == AF_INET6) {
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(ai->ai_addr);
            addr.SetIPv6(reinterpret_cast<const uint8_t*>(&sin6->sin6_addr));
            result.push_back(addr);
        }
    }

    freeaddrinfo(ai_result);
    return result;
}

bool LookupNumeric(const std::string& ip_string, CNetAddr2& out) {
    return CNetAddr2::ParseIP(ip_string, out);
}

std::vector<CService> LookupService(const std::string& name,
                                     uint16_t default_port,
                                     unsigned int max_results,
                                     bool allow_lookup) {
    std::vector<CService> result;

    std::string host;
    uint16_t port = default_port;

    // Try to split host:port
    if (!SplitHostPort(name, host, port)) {
        host = name;
        port = default_port;
    }

    auto addrs = LookupHost(host, max_results, allow_lookup);
    result.reserve(addrs.size());
    for (const auto& addr : addrs) {
        result.emplace_back(addr, port);
    }

    return result;
}

bool LookupServiceSingle(const std::string& name,
                          uint16_t default_port,
                          CService& out,
                          bool allow_lookup) {
    auto results = LookupService(name, default_port, 1, allow_lookup);
    if (results.empty()) return false;
    out = results[0];
    return true;
}

// ===========================================================================
// Socket operations
// ===========================================================================

int ConnectSocket(const CService& addr, int timeout_ms) {
    int fd = -1;

    if (addr.IsIPv4()) {
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    } else {
        fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    }

    if (fd < 0) {
        return -1;
    }

    // Set non-blocking for connect with timeout
    if (!SetSocketNonBlocking(fd)) {
        close(fd);
        return -1;
    }

    // Build sockaddr
    struct sockaddr_storage ss;
    std::memset(&ss, 0, sizeof(ss));
    socklen_t ss_len = 0;

    if (addr.IsIPv4()) {
        auto* sin = reinterpret_cast<struct sockaddr_in*>(&ss);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(addr.GetPort());
        uint32_t ipv4 = addr.GetIPv4();
        std::memcpy(&sin->sin_addr.s_addr, &ipv4, 4);
        ss_len = sizeof(struct sockaddr_in);
    } else {
        auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(&ss);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(addr.GetPort());
        std::memcpy(&sin6->sin6_addr, addr.GetBytes(), 16);
        ss_len = sizeof(struct sockaddr_in6);
    }

    int ret = connect(fd, reinterpret_cast<struct sockaddr*>(&ss), ss_len);
    if (ret == 0) {
        // Connected immediately (unlikely for non-blocking)
        // Set back to blocking
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        SetSocketNoDelay(fd);
        SetSocketKeepAlive(fd);
        return fd;
    }

    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    // Wait for connection with timeout
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    ret = poll(&pfd, 1, timeout_ms);
    if (ret <= 0) {
        // Timeout or error
        close(fd);
        return -1;
    }

    // Check for connection error
    int err = 0;
    socklen_t err_len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
    if (err != 0) {
        close(fd);
        return -1;
    }

    // Set back to blocking mode
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    SetSocketNoDelay(fd);
    SetSocketKeepAlive(fd);
    return fd;
}

bool SetSocketNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool SetSocketNoDelay(int fd) {
    int opt = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == 0;
}

bool SetSocketReuseAddr(int fd) {
    int opt = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0;
}

bool SetSocketKeepAlive(int fd) {
    int opt = 1;
    return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) == 0;
}

void CloseSocket(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

bool GetSocketLocalAddr(int fd, CService& out) {
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    std::memset(&ss, 0, sizeof(ss));

    if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&ss), &ss_len) != 0) {
        return false;
    }

    if (ss.ss_family == AF_INET) {
        auto* sin = reinterpret_cast<struct sockaddr_in*>(&ss);
        CNetAddr2 addr;
        uint32_t ipv4;
        std::memcpy(&ipv4, &sin->sin_addr.s_addr, 4);
        addr.SetIPv4(ipv4);
        out = CService(addr, ntohs(sin->sin_port));
        return true;
    } else if (ss.ss_family == AF_INET6) {
        auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(&ss);
        CNetAddr2 addr;
        addr.SetIPv6(reinterpret_cast<const uint8_t*>(&sin6->sin6_addr));
        out = CService(addr, ntohs(sin6->sin6_port));
        return true;
    }

    return false;
}

bool GetSocketPeerAddr(int fd, CService& out) {
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    std::memset(&ss, 0, sizeof(ss));

    if (getpeername(fd, reinterpret_cast<struct sockaddr*>(&ss), &ss_len) != 0) {
        return false;
    }

    if (ss.ss_family == AF_INET) {
        auto* sin = reinterpret_cast<struct sockaddr_in*>(&ss);
        CNetAddr2 addr;
        uint32_t ipv4;
        std::memcpy(&ipv4, &sin->sin_addr.s_addr, 4);
        addr.SetIPv4(ipv4);
        out = CService(addr, ntohs(sin->sin_port));
        return true;
    } else if (ss.ss_family == AF_INET6) {
        auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(&ss);
        CNetAddr2 addr;
        addr.SetIPv6(reinterpret_cast<const uint8_t*>(&sin6->sin6_addr));
        out = CService(addr, ntohs(sin6->sin6_port));
        return true;
    }

    return false;
}

// ===========================================================================
// Local address detection
// ===========================================================================

CNetAddr2 GetLocalAddress() {
    CNetAddr2 best;
    bool found = false;

    struct ifaddrs* ifa_list = nullptr;
    if (getifaddrs(&ifa_list) != 0) {
        return best;
    }

    for (struct ifaddrs* ifa = ifa_list; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        CNetAddr2 candidate;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            auto* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            uint32_t ipv4;
            std::memcpy(&ipv4, &sin->sin_addr.s_addr, 4);
            candidate.SetIPv4(ipv4);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
            candidate.SetIPv6(reinterpret_cast<const uint8_t*>(&sin6->sin6_addr));
        } else {
            continue;
        }

        if (!candidate.IsValid()) continue;

        // Prefer routable addresses
        if (candidate.IsRoutable()) {
            best = candidate;
            found = true;
        } else if (!found && !candidate.IsLoopback()) {
            best = candidate;
        }
    }

    freeifaddrs(ifa_list);
    return best;
}

CNetAddr2 GetLocalAddressForPeer(const CNetAddr2& peer) {
    // Create a UDP socket and "connect" to the peer to discover our
    // local address for that route
    int af = peer.IsIPv4() ? AF_INET : AF_INET6;
    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) return GetLocalAddress();

    struct sockaddr_storage ss;
    std::memset(&ss, 0, sizeof(ss));
    socklen_t ss_len = 0;

    if (peer.IsIPv4()) {
        auto* sin = reinterpret_cast<struct sockaddr_in*>(&ss);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(9333);
        uint32_t ipv4 = peer.GetIPv4();
        std::memcpy(&sin->sin_addr.s_addr, &ipv4, 4);
        ss_len = sizeof(struct sockaddr_in);
    } else {
        auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(&ss);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(9333);
        std::memcpy(&sin6->sin6_addr, peer.GetBytes(), 16);
        ss_len = sizeof(struct sockaddr_in6);
    }

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&ss), ss_len) != 0) {
        close(fd);
        return GetLocalAddress();
    }

    CService local;
    bool ok = GetSocketLocalAddr(fd, local);
    close(fd);

    if (ok && local.IsValid()) {
        return local;
    }
    return GetLocalAddress();
}

// ===========================================================================
// Reachability
// ===========================================================================

bool IsReachable(Network net) {
    std::lock_guard<std::mutex> lock(g_netbase_mutex);
    return net >= 0 && net < NET_MAX && g_reachable[net];
}

bool IsReachable(const CNetAddr2& addr) {
    return IsReachable(addr.GetNetwork());
}

void SetReachable(Network net, bool reachable) {
    std::lock_guard<std::mutex> lock(g_netbase_mutex);
    if (net >= 0 && net < NET_MAX) {
        g_reachable[net] = reachable;
    }
}

// ===========================================================================
// Proxy support
// ===========================================================================

void SetProxy(Network net, const ProxyConfig& config) {
    std::lock_guard<std::mutex> lock(g_netbase_mutex);
    if (net >= 0 && net < NET_MAX) {
        g_proxy[net] = config;
    }
}

bool GetProxy(Network net, ProxyConfig& config) {
    std::lock_guard<std::mutex> lock(g_netbase_mutex);
    if (net < 0 || net >= NET_MAX) return false;
    if (!g_proxy[net].IsValid()) return false;
    config = g_proxy[net];
    return true;
}

void SetNameProxy(const ProxyConfig& config) {
    std::lock_guard<std::mutex> lock(g_netbase_mutex);
    g_name_proxy = config;
    g_name_proxy_set = true;
}

bool GetNameProxy(ProxyConfig& config) {
    std::lock_guard<std::mutex> lock(g_netbase_mutex);
    if (!g_name_proxy_set) return false;
    config = g_name_proxy;
    return true;
}

bool HasProxy(Network net) {
    std::lock_guard<std::mutex> lock(g_netbase_mutex);
    if (net < 0 || net >= NET_MAX) return false;
    return g_proxy[net].IsValid();
}

int ConnectThroughProxy(const ProxyConfig& proxy,
                         const std::string& target_host,
                         uint16_t target_port,
                         int timeout_ms) {
    // Connect to the SOCKS5 proxy
    int fd = ConnectSocket(proxy.proxy, timeout_ms);
    if (fd < 0) return -1;

    // SOCKS5 handshake
    // 1. Send greeting: version(1) + nmethods(1) + methods(1..255)
    uint8_t greeting[3] = { 0x05, 0x01, 0x00 };  // No authentication
    ssize_t n = send(fd, greeting, sizeof(greeting), MSG_NOSIGNAL);
    if (n != sizeof(greeting)) {
        close(fd);
        return -1;
    }

    // 2. Receive server choice
    uint8_t response[2];
    n = recv(fd, response, sizeof(response), 0);
    if (n != 2 || response[0] != 0x05 || response[1] != 0x00) {
        close(fd);
        return -1;
    }

    // 3. Send connect request
    // version(1) + cmd(1) + rsv(1) + atyp(1) + addr + port(2)
    std::vector<uint8_t> connect_req;
    connect_req.push_back(0x05);  // version
    connect_req.push_back(0x01);  // connect command
    connect_req.push_back(0x00);  // reserved
    connect_req.push_back(0x03);  // domain name address type

    // Domain name: length + name
    if (target_host.size() > 255) {
        close(fd);
        return -1;
    }
    connect_req.push_back(static_cast<uint8_t>(target_host.size()));
    connect_req.insert(connect_req.end(), target_host.begin(), target_host.end());

    // Port (big-endian)
    connect_req.push_back(static_cast<uint8_t>(target_port >> 8));
    connect_req.push_back(static_cast<uint8_t>(target_port & 0xff));

    n = send(fd, connect_req.data(), connect_req.size(), MSG_NOSIGNAL);
    if (n != static_cast<ssize_t>(connect_req.size())) {
        close(fd);
        return -1;
    }

    // 4. Receive connect response
    uint8_t resp_header[4];
    n = recv(fd, resp_header, sizeof(resp_header), 0);
    if (n != 4 || resp_header[0] != 0x05 || resp_header[1] != 0x00) {
        close(fd);
        return -1;
    }

    // Read the bound address (we don't need it but must consume it)
    uint8_t atyp = resp_header[3];
    if (atyp == 0x01) {
        // IPv4: 4 bytes + 2 port
        uint8_t discard[6];
        recv(fd, discard, sizeof(discard), 0);
    } else if (atyp == 0x04) {
        // IPv6: 16 bytes + 2 port
        uint8_t discard[18];
        recv(fd, discard, sizeof(discard), 0);
    } else if (atyp == 0x03) {
        // Domain: 1 len + name + 2 port
        uint8_t dlen;
        recv(fd, &dlen, 1, 0);
        uint8_t discard[257];
        recv(fd, discard, dlen + 2, 0);
    } else {
        close(fd);
        return -1;
    }

    return fd;
}

// ===========================================================================
// Utility
// ===========================================================================

bool SplitHostPort(const std::string& str, std::string& host, uint16_t& port) {
    if (str.empty()) return false;

    // Handle [ipv6]:port
    if (str[0] == '[') {
        size_t close_bracket = str.find(']');
        if (close_bracket == std::string::npos) return false;
        host = str.substr(1, close_bracket - 1);
        if (close_bracket + 1 < str.size() && str[close_bracket + 1] == ':') {
            std::string port_str = str.substr(close_bracket + 2);
            int p = 0;
            try { p = std::stoi(port_str); } catch (...) { return false; }
            if (p <= 0 || p > 65535) return false;
            port = static_cast<uint16_t>(p);
        }
        return true;
    }

    // Count colons to distinguish IPv6 from host:port
    size_t colon_count = 0;
    for (char c : str) {
        if (c == ':') colon_count++;
    }

    if (colon_count > 1) {
        // Bare IPv6 address (no port)
        host = str;
        return true;
    }

    if (colon_count == 1) {
        // host:port
        size_t colon = str.find(':');
        host = str.substr(0, colon);
        std::string port_str = str.substr(colon + 1);
        int p = 0;
        try { p = std::stoi(port_str); } catch (...) { return false; }
        if (p <= 0 || p > 65535) return false;
        port = static_cast<uint16_t>(p);
        return true;
    }

    // No colon: just a hostname
    host = str;
    return true;
}

bool ValidateHostString(const std::string& str) {
    if (str.empty()) return false;
    if (str.size() > 255) return false;

    // No embedded nulls or control characters
    for (char c : str) {
        if (c == '\0') return false;
        if (static_cast<unsigned char>(c) < 0x20 && c != '\t') return false;
    }

    return true;
}

} // namespace flow
