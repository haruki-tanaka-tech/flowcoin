// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// flowcoin-miner — standalone CPU-only RandomX miner.
//
// Talks to a flowcoind node over HTTP JSON-RPC (`getblocktemplate`,
// `submitblock`). Each worker thread owns a RandomX VM and scans a disjoint
// stripe of the nonce space. Output style follows XMRig conventions: a banner
// of ` * LABEL      value` lines at start-up, then timestamped tagged events
// (`[YYYY-MM-DD HH:MM:SS.mmm]  TAG    message`), and a periodic
// `speed 10s/60s/15m` line.

#include "log.hpp"

#include <randomx.h>

extern "C" {
#include "../crypto/ed25519.h"
}

#include "../json/json.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <condition_variable>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;
using namespace miner;

// ===========================================================================
// Constants
// ===========================================================================

#define FLOWCOIN_MINER_VERSION "0.1.0"

static constexpr size_t HEADER_UNSIGNED = 92;
static constexpr size_t HEADER_SIGNED   = 188;

// ===========================================================================
// Hex helpers
// ===========================================================================

static inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static std::vector<uint8_t> hex_decode(const std::string& s) {
    std::vector<uint8_t> out;
    if (s.size() % 2 != 0) return out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = hex_nibble(s[i]);
        int lo = hex_nibble(s[i + 1]);
        if (hi < 0 || lo < 0) { out.clear(); return out; }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

static std::string hex_encode(const uint8_t* p, size_t n) {
    static const char k[] = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out[i * 2]     = k[p[i] >> 4];
        out[i * 2 + 1] = k[p[i] & 0xf];
    }
    return out;
}

// ===========================================================================
// CPU info (best-effort, POSIX)
// ===========================================================================

struct CpuInfo {
    std::string brand    = "unknown";
    size_t      threads  = std::thread::hardware_concurrency();
    bool        aes      = false;
    bool        is_64bit = (sizeof(void*) == 8);
};

static CpuInfo detect_cpu() {
    CpuInfo info;
    // Read /proc/cpuinfo to extract brand and AES flag (Linux).
    std::ifstream f("/proc/cpuinfo");
    std::string line;
    while (std::getline(f, line)) {
        if (info.brand == "unknown" && line.rfind("model name", 0) == 0) {
            auto p = line.find(':');
            if (p != std::string::npos) {
                auto b = line.substr(p + 1);
                // strip leading spaces
                while (!b.empty() && b.front() == ' ') b.erase(b.begin());
                info.brand = b;
            }
        }
        if (!info.aes && line.rfind("flags", 0) == 0) {
            info.aes = (line.find(" aes") != std::string::npos);
        }
    }
    if (info.threads == 0) info.threads = 1;
    return info;
}

// ===========================================================================
// Hashrate counter — rolling sum over a window.
// ===========================================================================

class Hashrate {
public:
    explicit Hashrate(std::chrono::seconds window)
        : window_(window) {}

    void add(uint64_t n) {
        using clock = std::chrono::steady_clock;
        auto now = clock::now();
        std::lock_guard<std::mutex> lock(mx_);
        samples_.push_back({now, n});
        trim(now);
    }

    /// Returns H/s over the window, or NaN if no samples are yet in range.
    double rate() const {
        using clock = std::chrono::steady_clock;
        auto now = clock::now();
        std::lock_guard<std::mutex> lock(mx_);
        // Non-const trim — drop samples older than the window.
        auto self = const_cast<Hashrate*>(this);
        self->trim(now);
        if (samples_.empty()) return std::numeric_limits<double>::quiet_NaN();
        uint64_t total = 0;
        for (auto& s : samples_) total += s.n;
        double elapsed = std::chrono::duration<double>(now - samples_.front().t).count();
        if (elapsed <= 0.0) return std::numeric_limits<double>::quiet_NaN();
        return static_cast<double>(total) / elapsed;
    }

private:
    struct Sample {
        std::chrono::steady_clock::time_point t;
        uint64_t n;
    };

    void trim(std::chrono::steady_clock::time_point now) {
        while (!samples_.empty() && now - samples_.front().t > window_) {
            samples_.pop_front();
        }
    }

    std::chrono::seconds window_;
    mutable std::mutex mx_;
    std::deque<Sample>  samples_;
};

static std::string format_hashrate(double h) {
    if (std::isnan(h)) return "N/A";
    char buf[32];
    if      (h >= 1e12) std::snprintf(buf, sizeof(buf), "%.2f TH/s", h / 1e12);
    else if (h >= 1e9)  std::snprintf(buf, sizeof(buf), "%.2f GH/s", h / 1e9);
    else if (h >= 1e6)  std::snprintf(buf, sizeof(buf), "%.2f MH/s", h / 1e6);
    else if (h >= 1e3)  std::snprintf(buf, sizeof(buf), "%.2f kH/s", h / 1e3);
    else                std::snprintf(buf, sizeof(buf), "%.2f H/s",  h);
    return buf;
}

// ===========================================================================
// HTTP client — minimal JSON-RPC over POSIX sockets.
// ===========================================================================

struct RpcAuth {
    std::string user;
    std::string pass;
};

struct RpcEndpoint {
    std::string host = "127.0.0.1";
    uint16_t    port = 9334;
    RpcAuth     auth;
};

static std::string base64_encode(const std::string& in) {
    static const char k[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    for (size_t i = 0; i < in.size(); i += 3) {
        uint32_t a = static_cast<uint8_t>(in[i]);
        uint32_t b = i + 1 < in.size() ? static_cast<uint8_t>(in[i + 1]) : 0;
        uint32_t c = i + 2 < in.size() ? static_cast<uint8_t>(in[i + 2]) : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out.push_back(k[(triple >> 18) & 0x3f]);
        out.push_back(k[(triple >> 12) & 0x3f]);
        out.push_back(i + 1 < in.size() ? k[(triple >> 6) & 0x3f] : '=');
        out.push_back(i + 2 < in.size() ? k[triple & 0x3f]        : '=');
    }
    return out;
}

static std::optional<std::string> http_post(const RpcEndpoint& ep, const std::string& body) {
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* ai = nullptr;
    std::string port_str = std::to_string(ep.port);
    if (::getaddrinfo(ep.host.c_str(), port_str.c_str(), &hints, &ai) != 0 || !ai) {
        return std::nullopt;
    }

    int sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) { ::freeaddrinfo(ai); return std::nullopt; }
    if (::connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
        ::close(sock); ::freeaddrinfo(ai); return std::nullopt;
    }
    ::freeaddrinfo(ai);

    std::string req;
    req.reserve(body.size() + 256);
    req += "POST / HTTP/1.1\r\n";
    req += "Host: " + ep.host + ":" + port_str + "\r\n";
    req += "Content-Type: application/json\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "Connection: close\r\n";
    if (!ep.auth.user.empty() || !ep.auth.pass.empty()) {
        req += "Authorization: Basic " + base64_encode(ep.auth.user + ":" + ep.auth.pass) + "\r\n";
    }
    req += "\r\n";
    req += body;

    size_t sent = 0;
    while (sent < req.size()) {
        ssize_t n = ::send(sock, req.data() + sent, req.size() - sent, 0);
        if (n <= 0) { ::close(sock); return std::nullopt; }
        sent += static_cast<size_t>(n);
    }

    std::string resp;
    char buf[4096];
    for (;;) {
        ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, static_cast<size_t>(n));
    }
    ::close(sock);

    auto pos = resp.find("\r\n\r\n");
    if (pos == std::string::npos) return std::nullopt;
    return resp.substr(pos + 4);
}

static std::optional<json> rpc_call(const RpcEndpoint& ep, const std::string& method,
                                     const json& params) {
    json req;
    req["jsonrpc"] = "2.0";
    req["id"]      = 1;
    req["method"]  = method;
    req["params"]  = params;
    auto resp = http_post(ep, req.dump());
    if (!resp) return std::nullopt;
    try {
        json j = json::parse(*resp);
        if (j.contains("error") && !j["error"].is_null()) return std::nullopt;
        if (!j.contains("result")) return std::nullopt;
        return j["result"];
    } catch (...) {
        return std::nullopt;
    }
}

// Read a cookie file (`user:pass` format, same as Bitcoin Core's .cookie).
static bool load_cookie(const std::string& path, RpcAuth& out) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string line;
    std::getline(f, line);
    auto p = line.find(':');
    if (p == std::string::npos) return false;
    out.user = line.substr(0, p);
    out.pass = line.substr(p + 1);
    return true;
}

// ===========================================================================
// Miner key (Ed25519) — stored at ~/.flowcoin/miner_key (32 bytes).
// ===========================================================================

struct MinerKey {
    uint8_t sk[32]{};
    uint8_t pk[32]{};
};

static std::string default_key_path() {
    const char* home = std::getenv("HOME");
    if (!home) home = "/tmp";
    return std::string(home) + "/.flowcoin/miner_key";
}

static bool read_file(const std::string& path, std::vector<uint8_t>& out, size_t expect) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    out.resize(expect);
    f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(expect));
    return f.gcount() == static_cast<std::streamsize>(expect);
}

static bool write_file(const std::string& path, const uint8_t* data, size_t n) {
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(n));
    return f.good();
}

static bool load_or_generate_key(const std::string& path, MinerKey& out) {
    std::vector<uint8_t> raw;
    if (read_file(path, raw, 32)) {
        std::memcpy(out.sk, raw.data(), 32);
        ed25519_publickey(out.sk, out.pk);
        return true;
    }
    // Generate a fresh keypair.
    std::random_device rd;
    for (int i = 0; i < 32; ++i) out.sk[i] = static_cast<uint8_t>(rd());
    ed25519_publickey(out.sk, out.pk);
    if (!write_file(path, out.sk, 32)) return false;
    return true;
}

// ===========================================================================
// Job — one block template to mine on. Immutable once handed to workers.
// ===========================================================================

struct Job {
    uint64_t                        id = 0;
    uint64_t                        height = 0;
    uint32_t                        nbits = 0;
    std::array<uint8_t, HEADER_UNSIGNED> header{};  // nonce bytes at [84..87]
    std::array<uint8_t, 32>         target_be{};    // big-endian target
    std::array<uint8_t, 32>         seed{};         // RandomX cache key
    std::vector<uint8_t>            coinbase_tx;    // for block assembly
    double                          difficulty = 0.0;
};

/// Compute rough "difficulty 1" style number from nbits for display.
static double nbits_to_difficulty(uint32_t nbits) {
    int shift = (nbits >> 24) & 0xff;
    double mantissa = static_cast<double>(nbits & 0x00ffffff);
    if (mantissa == 0.0) return 0.0;
    // Bitcoin-style: diff = (0x00ffff * 256^(0x1d-3)) / (mantissa * 256^(shift-3))
    double pow_limit = static_cast<double>(0xffff);
    int base_shift = 0x1d;
    double d = pow_limit / mantissa;
    int exp_diff = base_shift - shift;
    for (int i = 0; i < std::abs(exp_diff); ++i) d *= (exp_diff > 0 ? 256.0 : 1.0 / 256.0);
    return d;
}

// ===========================================================================
// Shared state between main thread and workers.
// ===========================================================================

struct SharedState {
    std::mutex                    mx;
    std::condition_variable       cv;
    std::shared_ptr<const Job>    job;          // current job (shared ptr for lock-free reads)
    std::atomic<uint64_t>         job_id{0};
    std::atomic<bool>             stop_flag{false};

    // Set by main thread to force all workers to exit (e.g. before a cache
    // swap). Workers observe both stop_flag and respawn_flag.
    std::atomic<bool>             respawn_flag{false};

    // When a worker finds a nonce, it sets these and signals the main thread.
    std::atomic<bool>             found_flag{false};
    uint32_t                      found_nonce = 0;
    std::array<uint8_t, 32>       found_hash{};
    uint64_t                      found_job_id = 0;

    // Global stats
    std::atomic<uint64_t>         total_hashes{0};
    std::atomic<uint64_t>         submits{0};
    std::atomic<uint64_t>         accepted{0};
    std::atomic<uint64_t>         rejected{0};
};

// ===========================================================================
// Worker thread — owns a RandomX VM and scans its nonce stripe.
// ===========================================================================

static void worker_main(size_t thread_id, size_t num_threads,
                         randomx_cache* cache, randomx_dataset* dataset,
                         randomx_flags flags, SharedState& state,
                         Hashrate* hr10, Hashrate* hr60, Hashrate* hr900) {
    randomx_vm* vm = randomx_create_vm(flags, cache, dataset);
    if (!vm) {
        Log::error(tag::randomx(), "create_vm failed in thread %zu", thread_id);
        return;
    }

    std::shared_ptr<const Job> last_job;
    std::array<uint8_t, HEADER_UNSIGNED> local{};
    std::array<uint8_t, 32> target{};
    uint64_t local_job_id = 0;
    uint64_t hashes_since_report = 0;
    auto last_report = std::chrono::steady_clock::now();

    while (!state.stop_flag.load(std::memory_order_relaxed) &&
           !state.respawn_flag.load(std::memory_order_relaxed)) {
        // Pick up the current job if it has advanced.
        uint64_t jid = state.job_id.load(std::memory_order_acquire);
        if (jid != local_job_id) {
            std::shared_ptr<const Job> j;
            {
                std::lock_guard<std::mutex> lock(state.mx);
                j = state.job;
            }
            if (!j) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            last_job = j;
            local    = j->header;
            target   = j->target_be;
            local_job_id = j->id;
        }

        // Stripe: this thread visits nonces congruent to thread_id (mod num_threads).
        uint32_t nonce = static_cast<uint32_t>(thread_id);
        while (!state.stop_flag.load(std::memory_order_relaxed) &&
               !state.respawn_flag.load(std::memory_order_relaxed) &&
               state.job_id.load(std::memory_order_relaxed) == local_job_id) {
            local[84] = static_cast<uint8_t>(nonce);
            local[85] = static_cast<uint8_t>(nonce >> 8);
            local[86] = static_cast<uint8_t>(nonce >> 16);
            local[87] = static_cast<uint8_t>(nonce >> 24);

            uint8_t h[32];
            randomx_calculate_hash(vm, local.data(), local.size(), h);
            ++hashes_since_report;
            state.total_hashes.fetch_add(1, std::memory_order_relaxed);

            // Compare lexicographically (big-endian order).
            if (std::memcmp(h, target.data(), 32) <= 0) {
                state.found_nonce = nonce;
                std::memcpy(state.found_hash.data(), h, 32);
                state.found_job_id = local_job_id;
                state.found_flag.store(true, std::memory_order_release);
                state.cv.notify_all();
                break;
            }

            // Periodic hashrate report (every ~512 hashes per thread).
            if ((hashes_since_report & 0x1FF) == 0) {
                auto now = std::chrono::steady_clock::now();
                auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_report).count();
                if (dt > 0) {
                    hr10->add(hashes_since_report);
                    hr60->add(hashes_since_report);
                    hr900->add(hashes_since_report);
                    hashes_since_report = 0;
                    last_report = now;
                }
            }

            if (static_cast<size_t>(UINT32_MAX - nonce) < num_threads) break;
            nonce += static_cast<uint32_t>(num_threads);
        }
    }

    randomx_destroy_vm(vm);
}

// ===========================================================================
// Full block serialisation (92 + 32 + 64 header + CompactSize(ntx) + coinbase).
// ===========================================================================

static void encode_compact_size(std::vector<uint8_t>& out, uint64_t v) {
    if (v < 253)            { out.push_back(static_cast<uint8_t>(v)); }
    else if (v <= 0xFFFF)   { out.push_back(253); out.push_back(v & 0xff); out.push_back((v >> 8) & 0xff); }
    else if (v <= 0xFFFFFFFFULL) {
        out.push_back(254);
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
    } else {
        out.push_back(255);
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
}

static std::string serialize_signed_block(const Job& j, uint32_t winning_nonce,
                                           const MinerKey& key) {
    std::array<uint8_t, HEADER_UNSIGNED> hdr = j.header;
    hdr[84] = static_cast<uint8_t>(winning_nonce);
    hdr[85] = static_cast<uint8_t>(winning_nonce >> 8);
    hdr[86] = static_cast<uint8_t>(winning_nonce >> 16);
    hdr[87] = static_cast<uint8_t>(winning_nonce >> 24);

    ed25519_signature sig;
    ed25519_sign(hdr.data(), hdr.size(), key.sk, key.pk, sig);

    std::vector<uint8_t> out;
    out.reserve(HEADER_SIGNED + 1 + j.coinbase_tx.size());
    out.insert(out.end(), hdr.begin(), hdr.end());
    out.insert(out.end(), key.pk, key.pk + 32);
    out.insert(out.end(), sig, sig + 64);
    encode_compact_size(out, 1);  // one transaction (coinbase)
    out.insert(out.end(), j.coinbase_tx.begin(), j.coinbase_tx.end());
    return hex_encode(out.data(), out.size());
}

// ===========================================================================
// Banner
// ===========================================================================

static void print_banner(const CpuInfo& cpu, size_t threads, const RpcEndpoint& ep,
                          const std::string& address) {
    auto line = [](const char* label, const std::string& value) {
        Log::banner(GREEN_BOLD(" * ") WHITE_BOLD_S "%-13s" CLEAR "%s",
                    label, value.c_str());
    };

    std::string aboutv = "flowcoin-miner/" FLOWCOIN_MINER_VERSION " ";
#ifdef __clang__
    aboutv += "clang/" + std::to_string(__clang_major__) + "." + std::to_string(__clang_minor__);
#elif defined(__GNUC__)
    aboutv += "gcc/" + std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__);
#else
    aboutv += "unknown";
#endif
    line("ABOUT", aboutv);
    line("LIBS", std::string("RandomX nlohmann-json/3.x"));

    std::string cpuline = cpu.brand + "  " +
        (cpu.is_64bit ? GREEN_BOLD("64-bit") : RED_BOLD("32-bit")) + " " +
        (cpu.aes ? GREEN_BOLD("AES") : RED_BOLD("-AES"));
    line("CPU", cpuline);
    line("", std::string(BLACK_BOLD_S "threads:") + CYAN_BOLD_S + std::to_string(cpu.threads) + CLEAR);

    std::string ep_str = ep.host + ":" + std::to_string(ep.port);
    line("NODE", CYAN_BOLD_S + ep_str + CLEAR);
    line("ADDRESS", address.empty() ? (BLACK_BOLD("inherited from node wallet"))
                                    : (CYAN_BOLD_S + address + CLEAR));
    line("ALGO", MAGENTA_BOLD("randomx"));
    line("THREADS", std::string(CYAN_BOLD_S) + std::to_string(threads) + CLEAR);
    Log::banner("");
}

// ===========================================================================
// Benchmark mode — run RandomX for N seconds on all threads.
// ===========================================================================

static int run_benchmark(size_t threads, int seconds, bool full_mem) {
    randomx_flags flags = randomx_get_flags() | RANDOMX_FLAG_JIT;
    if (full_mem) flags |= RANDOMX_FLAG_FULL_MEM;

    randomx_cache* cache = randomx_alloc_cache(flags);
    if (!cache) { Log::error(tag::bench(), "alloc_cache failed"); return 1; }
    const char* key = "flowcoin-miner benchmark";
    randomx_init_cache(cache, key, std::strlen(key));

    randomx_dataset* ds = nullptr;
    if (full_mem) {
        ds = randomx_alloc_dataset(flags);
        if (!ds) { Log::error(tag::bench(), "alloc_dataset failed"); randomx_release_cache(cache); return 1; }
        unsigned long total = randomx_dataset_item_count();
        auto t0 = std::chrono::steady_clock::now();
        randomx_init_dataset(ds, cache, 0, total);
        auto t1 = std::chrono::steady_clock::now();
        Log::info(tag::bench(), "dataset ready (%.0f MB) (%" PRId64 " ms)",
                  (total * 64.0) / (1024.0 * 1024.0),
                  static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count()));
    }

    std::atomic<bool>     stop{false};
    std::atomic<uint64_t> total{0};
    std::vector<std::thread> ts;
    auto t0 = std::chrono::steady_clock::now();

    for (size_t i = 0; i < threads; ++i) {
        ts.emplace_back([&, i]() {
            randomx_vm* vm = randomx_create_vm(flags, cache, ds);
            if (!vm) return;
            uint8_t buf[76];
            std::memset(buf, 0, sizeof(buf));
            buf[0] = static_cast<uint8_t>(i);  // differentiate threads
            uint8_t h[32];
            uint64_t local = 0;
            while (!stop.load(std::memory_order_relaxed)) {
                ++local;
                buf[4] = static_cast<uint8_t>(local);
                buf[5] = static_cast<uint8_t>(local >> 8);
                buf[6] = static_cast<uint8_t>(local >> 16);
                buf[7] = static_cast<uint8_t>(local >> 24);
                randomx_calculate_hash(vm, buf, sizeof(buf), h);
            }
            total.fetch_add(local, std::memory_order_relaxed);
            randomx_destroy_vm(vm);
        });
    }

    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    stop.store(true);
    for (auto& t : ts) t.join();

    auto t1 = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();
    double rate = elapsed > 0.0 ? total.load() / elapsed : 0.0;

    Log::info(tag::bench(), "speed " CYAN_BOLD_S "%s" CLEAR "  threads=" CYAN_BOLD_S "%zu" CLEAR
              "  mode=%s  elapsed=%.2fs  hashes=%" PRIu64,
              format_hashrate(rate).c_str(), threads,
              full_mem ? "fast" : "light", elapsed, total.load());

    if (ds)    randomx_release_dataset(ds);
    randomx_release_cache(cache);
    return 0;
}

// ===========================================================================
// Main
// ===========================================================================

struct Args {
    std::string url      = "http://127.0.0.1:9334";
    std::string user;
    std::string pass;
    std::string cookie;
    std::string address;
    std::string key_path = default_key_path();
    size_t      threads  = 0;   // auto
    int         bench    = 0;   // 0 = mine, >0 = benchmark seconds
    bool        full_mem = true;
    bool        colors   = true;
};

static void print_usage() {
    std::puts(
        "flowcoin-miner " FLOWCOIN_MINER_VERSION "\n"
        "Usage: flowcoin-miner [options]\n"
        "\n"
        "  -o, --url URL           node RPC URL (default: http://127.0.0.1:9334)\n"
        "  -u, --user USER         HTTP Basic user\n"
        "  -p, --pass PASS         HTTP Basic password\n"
        "      --cookie PATH       read auth from Bitcoin-Core-style cookie file\n"
        "  -t, --threads N         worker threads (default: all logical cores)\n"
        "  -a, --address ADDR      coinbase bech32m address (default: node's wallet)\n"
        "      --key PATH          miner signing key (default: ~/.flowcoin/miner_key)\n"
        "  -b, --benchmark SECS    run RandomX benchmark for SECS seconds and exit\n"
        "      --light             use 256 MB light mode instead of 2 GB fast mode\n"
        "      --no-color          disable ANSI colours\n"
        "  -h, --help              this message\n");
}

static bool parse_url(const std::string& url, RpcEndpoint& ep) {
    std::string s = url;
    auto p = s.find("://");
    if (p != std::string::npos) s = s.substr(p + 3);
    auto slash = s.find('/');
    if (slash != std::string::npos) s = s.substr(0, slash);
    auto colon = s.rfind(':');
    if (colon == std::string::npos) { ep.host = s; return true; }
    ep.host = s.substr(0, colon);
    ep.port = static_cast<uint16_t>(std::atoi(s.c_str() + colon + 1));
    return true;
}

int main(int argc, char** argv) {
    Args a;

    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i];
        auto take = [&](std::string& dst) {
            if (++i < argc) dst = argv[i];
        };
        if      (k == "-h" || k == "--help")      { print_usage(); return 0; }
        else if (k == "-o" || k == "--url")       take(a.url);
        else if (k == "-u" || k == "--user")      take(a.user);
        else if (k == "-p" || k == "--pass")      take(a.pass);
        else if (k == "--cookie")                 take(a.cookie);
        else if (k == "-t" || k == "--threads")   { std::string s; take(s); a.threads = std::stoul(s); }
        else if (k == "-a" || k == "--address")   take(a.address);
        else if (k == "--key")                    take(a.key_path);
        else if (k == "-b" || k == "--benchmark") { std::string s; take(s); a.bench = std::stoi(s); }
        else if (k == "--light")                  a.full_mem = false;
        else if (k == "--no-color")               a.colors = false;
        else { std::fprintf(stderr, "unknown option: %s\n", k.c_str()); return 2; }
    }

    Log::colors() = a.colors && ::isatty(fileno(stdout));

    RpcEndpoint ep;
    parse_url(a.url, ep);
    if (!a.cookie.empty()) {
        if (!load_cookie(a.cookie, ep.auth)) {
            Log::error(tag::config(), "cannot read cookie file %s", a.cookie.c_str());
            return 3;
        }
    } else {
        ep.auth.user = a.user;
        ep.auth.pass = a.pass;
    }

    CpuInfo cpu = detect_cpu();
    size_t  threads = a.threads ? a.threads : cpu.threads;

    print_banner(cpu, threads, ep, a.address);

    if (a.bench > 0) {
        return run_benchmark(threads, a.bench, a.full_mem);
    }

    // Load signing key.
    MinerKey key;
    if (!load_or_generate_key(a.key_path, key)) {
        Log::error(tag::config(), "cannot load or create miner key at %s", a.key_path.c_str());
        return 3;
    }
    Log::info(tag::config(), "miner pubkey " CYAN_BOLD_S "%s" CLEAR,
              hex_encode(key.pk, 32).substr(0, 16).c_str());

    // Initial connectivity check.
    {
        auto r = rpc_call(ep, "getblockcount", json::array());
        if (!r) {
            Log::error(tag::net(), "cannot reach node at %s:%u", ep.host.c_str(), ep.port);
            return 4;
        }
        Log::info(tag::net(), "connected to " CYAN_BOLD_S "%s:%u" CLEAR
                  "  height=" CYAN_BOLD_S "%s" CLEAR,
                  ep.host.c_str(), ep.port, r->dump().c_str());
    }

    // Allocate RandomX cache + optional dataset.
    randomx_flags flags = randomx_get_flags() | RANDOMX_FLAG_JIT;
    if (a.full_mem) flags |= RANDOMX_FLAG_FULL_MEM;
    randomx_cache* cache = randomx_alloc_cache(flags);
    if (!cache) { Log::error(tag::randomx(), "alloc_cache failed"); return 5; }
    randomx_dataset* dataset = nullptr;
    if (a.full_mem) {
        dataset = randomx_alloc_dataset(flags);
        if (!dataset) { Log::error(tag::randomx(), "alloc_dataset failed"); return 5; }
    }

    // Signal handling for clean shutdown.
    static SharedState state;
    std::signal(SIGINT,  [](int){ state.stop_flag.store(true); state.cv.notify_all(); });
    std::signal(SIGTERM, [](int){ state.stop_flag.store(true); state.cv.notify_all(); });

    // Start workers (they wait on initial job).
    std::vector<std::thread> workers;
    Hashrate hr10(std::chrono::seconds(10));
    Hashrate hr60(std::chrono::seconds(60));
    Hashrate hr900(std::chrono::seconds(900));
    std::array<uint8_t, 32> current_seed{};

    auto spawn_workers = [&]() {
        workers.clear();
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back(worker_main, i, threads, cache, dataset, flags,
                                  std::ref(state), &hr10, &hr60, &hr900);
        }
    };

    // Background speed-line printer.
    std::thread speed_thread([&]() {
        while (!state.stop_flag.load(std::memory_order_relaxed)) {
            std::unique_lock<std::mutex> lk(state.mx);
            state.cv.wait_for(lk, std::chrono::seconds(10));
            if (state.stop_flag.load()) break;
            Log::info(tag::miner(),
                "speed 10s/60s/15m " CYAN_BOLD_S "%s" CLEAR " " CYAN_S "%s %s" CLEAR,
                format_hashrate(hr10.rate()).c_str(),
                format_hashrate(hr60.rate()).c_str(),
                format_hashrate(hr900.rate()).c_str());
        }
    });

    // Main coordinator loop: poll getblocktemplate, update job, submit found blocks.
    uint64_t next_job_id = 1;
    auto last_template_poll = std::chrono::steady_clock::now() - std::chrono::seconds(999);

    while (!state.stop_flag.load(std::memory_order_relaxed)) {
        // Submit any found block.
        if (state.found_flag.exchange(false)) {
            std::shared_ptr<const Job> j;
            {
                std::lock_guard<std::mutex> lock(state.mx);
                j = state.job;
            }
            if (j && state.found_job_id == j->id) {
                std::string hex = serialize_signed_block(*j, state.found_nonce, key);
                auto ts = std::chrono::steady_clock::now();
                state.submits.fetch_add(1);
                auto r = rpc_call(ep, "submitblock", json::array({hex}));
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - ts).count();
                bool ok = r && (r->is_null() || (r->is_string() && r->get<std::string>().empty()));
                if (ok) {
                    state.accepted.fetch_add(1);
                    Log::info(tag::miner(),
                        GREEN_BOLD("accepted") " (%" PRIu64 "/%" PRIu64 ") height "
                        CYAN_BOLD_S "%" PRIu64 CLEAR "  nonce " CYAN_BOLD_S "%u" CLEAR
                        "  (%" PRId64 " ms)",
                        state.accepted.load(), state.submits.load(),
                        j->height, state.found_nonce,
                        static_cast<int64_t>(ms));
                } else {
                    state.rejected.fetch_add(1);
                    std::string reason = r ? r->dump() : "no response";
                    Log::info(tag::miner(),
                        RED_BOLD("rejected") " (%" PRIu64 "/%" PRIu64 ") height "
                        CYAN_BOLD_S "%" PRIu64 CLEAR "  " RED_S "%s" CLEAR
                        "  (%" PRId64 " ms)",
                        state.rejected.load(), state.submits.load(),
                        j->height, reason.c_str(),
                        static_cast<int64_t>(ms));
                }
                // Force template refresh after a submit.
                last_template_poll = std::chrono::steady_clock::now() - std::chrono::seconds(999);
            }
        }

        // Poll for a new template every ~3 seconds (or immediately after a submit).
        auto now = std::chrono::steady_clock::now();
        if (now - last_template_poll > std::chrono::seconds(3)) {
            last_template_poll = now;
            json params = a.address.empty() ? json::array() : json::array({a.address});
            auto r = rpc_call(ep, "getblocktemplate", params);
            if (!r) {
                Log::warn(tag::net(), "getblocktemplate failed");
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
            const json& t = *r;

            auto j = std::make_shared<Job>();
            j->id     = next_job_id++;
            j->height = t.value("height", 0ULL);
            j->nbits  = t.value("nbits",  0u);
            j->difficulty = nbits_to_difficulty(j->nbits);

            auto prev    = hex_decode(t.value("previousblockhash", std::string()));
            auto merkle  = hex_decode(t.value("merkle_root",       std::string()));
            auto target  = hex_decode(t.value("target",            std::string()));
            auto seedhex = hex_decode(t.value("seed_hash",         std::string()));
            auto cbhex   = hex_decode(t.value("coinbase_tx",       std::string()));

            if (prev.size() != 32 || merkle.size() != 32 || target.size() != 32 ||
                seedhex.size() != 32) {
                Log::warn(tag::net(), "malformed template");
                continue;
            }

            std::array<uint8_t, HEADER_UNSIGNED> hdr{};
            std::memcpy(hdr.data() +  0, prev.data(),   32);
            std::memcpy(hdr.data() + 32, merkle.data(), 32);
            uint64_t h = j->height;
            for (int i = 0; i < 8; ++i) hdr[64 + i] = static_cast<uint8_t>(h >> (i * 8));
            int64_t ts = t.value("curtime", int64_t{0});
            for (int i = 0; i < 8; ++i) hdr[72 + i] = static_cast<uint8_t>(ts >> (i * 8));
            for (int i = 0; i < 4; ++i) hdr[80 + i] = static_cast<uint8_t>(j->nbits >> (i * 8));
            // nonce bytes [84..87] stay zero; workers write them.
            uint32_t ver = t.value("version", 1u);
            for (int i = 0; i < 4; ++i) hdr[88 + i] = static_cast<uint8_t>(ver >> (i * 8));
            j->header = hdr;

            // Target in the RPC response is little-endian display; flip to big-endian
            // so the byte-wise memcmp against the hash is correct.
            for (size_t i = 0; i < 32; ++i) j->target_be[i] = target[31 - i];
            std::memcpy(j->seed.data(), seedhex.data(), 32);
            j->coinbase_tx = cbhex;

            // If the seed changed, re-initialise the RandomX cache + dataset.
            if (j->seed != current_seed) {
                // Ask workers to exit so we can swap the cache safely.
                state.respawn_flag.store(true);
                for (auto& t : workers) if (t.joinable()) t.join();
                state.respawn_flag.store(false);

                auto t0 = std::chrono::steady_clock::now();
                randomx_init_cache(cache, j->seed.data(), j->seed.size());
                auto t1 = std::chrono::steady_clock::now();
                Log::info(tag::randomx(), "cache seed=" CYAN_BOLD_S "%s" CLEAR
                          "  (%" PRId64 " ms)",
                          hex_encode(j->seed.data(), 32).substr(0, 16).c_str(),
                          static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count()));

                if (dataset) {
                    auto d0 = std::chrono::steady_clock::now();
                    unsigned long total_items = randomx_dataset_item_count();
                    // Parallelise dataset init across `threads`.
                    std::vector<std::thread> init_threads;
                    for (size_t ti = 0; ti < threads; ++ti) {
                        unsigned long start = total_items * ti / threads;
                        unsigned long end   = total_items * (ti + 1) / threads;
                        init_threads.emplace_back([cache, dataset, start, end]() {
                            randomx_init_dataset(dataset, cache, start, end - start);
                        });
                    }
                    for (auto& th : init_threads) th.join();
                    auto d1 = std::chrono::steady_clock::now();
                    Log::info(tag::randomx(), "dataset ready (%.0f MB)  (%" PRId64 " ms)",
                              (total_items * 64.0) / (1024.0 * 1024.0),
                              static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(d1 - d0).count()));
                }

                current_seed = j->seed;
                spawn_workers();
            }

            {
                std::lock_guard<std::mutex> lock(state.mx);
                state.job = j;
            }
            state.job_id.store(j->id, std::memory_order_release);

            char diff_buf[32];
            std::snprintf(diff_buf, sizeof(diff_buf), "%.3f", j->difficulty);
            Log::info(tag::net(),
                MAGENTA_BOLD("new job") " from " WHITE_BOLD_S "%s:%u" CLEAR
                "  height " CYAN_BOLD_S "%" PRIu64 CLEAR
                "  diff "   CYAN_BOLD_S "%s" CLEAR
                "  algo " WHITE_BOLD("randomx"),
                ep.host.c_str(), ep.port, j->height, diff_buf);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // Shutdown.
    Log::info(tag::signals(), "stopping");
    state.stop_flag.store(true);
    state.cv.notify_all();
    for (auto& t : workers) if (t.joinable()) t.join();
    if (speed_thread.joinable()) speed_thread.join();

    if (dataset) randomx_release_dataset(dataset);
    randomx_release_cache(cache);

    Log::info(tag::miner(), "stopped. total=%" PRIu64 "  accepted=%" PRIu64 "  rejected=%" PRIu64,
              state.submits.load(), state.accepted.load(), state.rejected.load());
    return 0;
}
