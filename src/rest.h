// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// REST API server for FlowCoin.
// Provides a read-only HTTP interface for querying blockchain data
// in JSON, binary, and hex formats. Designed for light clients,
// block explorers, and external tools.
//
// Endpoints:
//   GET /rest/block/<hash>.[json|bin|hex]
//   GET /rest/block/notxdetails/<hash>.[json|bin|hex]
//   GET /rest/headers/<count>/<hash>.[json|bin|hex]
//   GET /rest/tx/<hash>.[json|bin|hex]
//   GET /rest/getutxos/<txid>-<vout>/....[json|bin|hex]
//   GET /rest/blockhashbyheight/<height>.[json|bin|hex]
//   GET /rest/chaininfo.[json]
//   GET /rest/mempool/info.[json]
//   GET /rest/mempool/contents.[json]

#ifndef FLOWCOIN_REST_H
#define FLOWCOIN_REST_H

#include "chain/chainstate.h"
#include "mempool/mempool.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/types.h"

#include <cstdint>
#include <string>
#include <vector>

#include "json/json.hpp"

namespace flow {

// ============================================================================
// REST response
// ============================================================================

struct RestResponse {
    int status_code = 200;
    std::string content_type;
    std::vector<uint8_t> body;

    /// Convenience: create a 200 JSON response.
    static RestResponse json_ok(const std::vector<uint8_t>& body);

    /// Convenience: create a 200 binary response.
    static RestResponse binary_ok(const std::vector<uint8_t>& body);

    /// Convenience: create a 200 hex response.
    static RestResponse hex_ok(const std::vector<uint8_t>& body);

    /// Convenience: create an error response.
    static RestResponse error(int status_code, const std::string& message);

    /// Convenience: create a 404 not found response.
    static RestResponse not_found(const std::string& message);

    /// Convenience: create a 400 bad request response.
    static RestResponse bad_request(const std::string& message);
};

// ============================================================================
// Output format
// ============================================================================

enum class RestFormat {
    JSON,
    BINARY,
    HEX,
};

/// Parse a format extension string ("json", "bin", "hex").
/// Returns JSON by default.
RestFormat parse_rest_format(const std::string& ext);

/// Get the Content-Type header for a format.
const char* rest_content_type(RestFormat fmt);

// ============================================================================
// REST server
// ============================================================================

class RestServer {
public:
    /// Construct with references to chain state and mempool.
    RestServer(ChainState& chain, Mempool& mempool);

    /// Handle a REST request.
    /// @param method  HTTP method (GET, POST, etc.)
    /// @param path    Request path (e.g., "/rest/block/abc123.json")
    /// @param query   Query string (e.g., "verbose=1")
    /// @return        Response with status code, content type, and body.
    RestResponse handle_request(const std::string& method,
                                 const std::string& path,
                                 const std::string& query);

    /// Set the maximum number of headers returned by /rest/headers.
    void set_max_headers(int max) { max_headers_ = max; }

    /// Set the maximum number of UTXOs returned by /rest/getutxos.
    void set_max_utxos(int max) { max_utxos_ = max; }

private:
    ChainState& chain_;
    Mempool& mempool_;
    int max_headers_ = 2000;
    int max_utxos_ = 100;

    // ---- Endpoint handlers -------------------------------------------------

    RestResponse handle_block(const std::string& hash_str,
                               RestFormat format,
                               bool with_tx_details);

    RestResponse handle_headers(int count,
                                 const std::string& hash_str,
                                 RestFormat format);

    RestResponse handle_tx(const std::string& hash_str,
                            RestFormat format);

    RestResponse handle_getutxos(const std::string& params,
                                  RestFormat format);

    RestResponse handle_blockhashbyheight(const std::string& height_str,
                                           RestFormat format);

    RestResponse handle_chaininfo();

    RestResponse handle_mempool_info();

    RestResponse handle_mempool_contents();

    // ---- Serialization helpers ---------------------------------------------

    /// Convert a block to JSON.
    std::vector<uint8_t> block_to_json(const CBlock& block,
                                        bool with_tx_details);

    /// Convert a block header to JSON.
    std::vector<uint8_t> header_to_json(const CBlockHeader& header,
                                         uint64_t height,
                                         int confirmations);

    /// Convert a transaction to JSON.
    std::vector<uint8_t> tx_to_json(const CTransaction& tx,
                                     const uint256& block_hash,
                                     uint64_t block_height);

    /// Convert a UTXO entry to JSON.
    std::vector<uint8_t> utxo_to_json(const uint256& txid, uint32_t vout,
                                       const UTXOEntry& entry);

    /// Convert binary data to hex-encoded bytes.
    static std::vector<uint8_t> to_hex_bytes(const std::vector<uint8_t>& data);

    /// Convert a uint256 to a hex string.
    static std::string hash_to_hex(const uint256& hash);

    /// Parse a hex string to uint256.
    static bool hex_to_hash(const std::string& hex, uint256& hash);

    // ---- Path parsing ------------------------------------------------------

    struct ParsedPath {
        std::string endpoint;    // e.g., "block", "tx", "chaininfo"
        std::string param1;      // e.g., block hash, height
        std::string param2;      // e.g., count for headers
        RestFormat format = RestFormat::JSON;
        bool valid = false;
    };

    /// Parse a REST path into components.
    static ParsedPath parse_path(const std::string& path);

    /// Split a path string by '/'.
    static std::vector<std::string> split_path(const std::string& path);

    /// Extract the format extension from a filename.
    static std::pair<std::string, std::string> split_extension(
        const std::string& filename);
};

} // namespace flow

#endif // FLOWCOIN_REST_H
