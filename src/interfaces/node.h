// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Abstract node interface for GUI and external consumers.
// Provides a clean, stable API surface for querying and controlling
// a running FlowCoin node without depending on internal implementation
// details. The GUI and RPC proxy use this interface exclusively.

#ifndef FLOWCOIN_INTERFACES_NODE_H
#define FLOWCOIN_INTERFACES_NODE_H

#include "util/types.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace flow {
class ChainState;
class Wallet;
class Mempool;
class NetManager;
struct NodeContext;
}

namespace flow::interfaces {

// ============================================================================
// Node interface
// ============================================================================

class Node {
public:
    virtual ~Node() = default;

    // ---- Lifecycle ---------------------------------------------------------

    /// Parse arguments and initialize configuration.
    virtual bool init(int argc, char* argv[]) = 0;

    /// Start all node subsystems (chain, network, RPC, mining).
    virtual bool start() = 0;

    /// Begin shutdown sequence. Non-blocking.
    virtual void stop() = 0;

    /// Block until shutdown is complete.
    virtual void wait_for_shutdown() = 0;

    /// Check if the node is currently running.
    virtual bool is_running() = 0;

    // ---- Chain information -------------------------------------------------

    /// Get the height of the active chain tip.
    virtual uint64_t get_height() = 0;

    /// Get the hash of the best (tip) block.
    virtual uint256 get_best_block_hash() = 0;

    /// Get the current mining difficulty.
    virtual double get_difficulty() = 0;

    /// Check if the node is performing initial block download.
    virtual bool is_initial_block_download() = 0;

    /// Get the verification progress as a fraction [0.0, 1.0].
    virtual double get_verification_progress() = 0;

    /// Get the timestamp of the most recent block.
    virtual int64_t get_last_block_time() = 0;

    /// Get the total number of blocks validated.
    virtual uint64_t get_block_count() = 0;

    /// Get the hash of a block at a specific height.
    virtual uint256 get_block_hash(uint64_t height) = 0;

    /// Get the current chain work as a decimal string.
    virtual std::string get_chain_work() = 0;

    // ---- Network information -----------------------------------------------

    /// Get the number of active peer connections.
    virtual int get_num_connections() = 0;

    /// Get total bytes sent since node start.
    virtual int64_t get_total_bytes_sent() = 0;

    /// Get total bytes received since node start.
    virtual int64_t get_total_bytes_recv() = 0;

    /// Get the network name (mainnet, testnet, regtest).
    virtual std::string get_network_name() = 0;

    /// Check if the node is listening for connections.
    virtual bool is_listening() = 0;

    /// Get the local node's external addresses.
    virtual std::vector<std::string> get_local_addresses() = 0;

    // ---- Mempool -----------------------------------------------------------

    /// Get the number of transactions in the mempool.
    virtual size_t get_mempool_size() = 0;

    /// Get the minimum fee rate to enter the mempool (sat/kB).
    virtual Amount get_mempool_min_fee() = 0;

    /// Get the total memory usage of the mempool in bytes.
    virtual size_t get_mempool_bytes() = 0;

    // ---- Wallet (simplified) -----------------------------------------------

    /// Get the confirmed wallet balance.
    virtual Amount get_balance() = 0;

    /// Get a new receiving address.
    virtual std::string get_new_address() = 0;

    /// Send coins to an address. Returns the txid hex on success.
    virtual std::string send_to_address(const std::string& addr,
                                         Amount amount) = 0;

    /// Get the unconfirmed balance.
    virtual Amount get_unconfirmed_balance() = 0;

    // ---- Mining ------------------------------------------------------------

    /// Check if the miner is currently running.
    virtual bool is_mining() = 0;

    /// Get estimated network hashrate (hashes/second).
    virtual double get_network_hashrate() = 0;

    /// Get the current mining difficulty target (nbits).
    virtual uint32_t get_nbits() = 0;

    // ---- Model (Proof-of-Training) -----------------------------------------

    /// Get the total parameter count of the consensus model.
    virtual size_t get_model_param_count() = 0;

    /// Get the current validation loss of the model.
    virtual float get_model_val_loss() = 0;

    /// Get the hash of the current model state.
    virtual uint256 get_model_hash() = 0;

    // ---- Fee estimation ----------------------------------------------------

    /// Estimate the fee rate (sat/kB) for confirmation within target blocks.
    virtual Amount estimate_smart_fee(int target_blocks) = 0;

    // ---- Notifications -----------------------------------------------------

    using BlockTipCallback = std::function<void(
        uint64_t height, int64_t timestamp, double progress)>;
    using HeaderTipCallback = std::function<void(
        uint64_t height, int64_t timestamp, double progress)>;
    using AlertCallback = std::function<void(const std::string& message)>;
    using ShutdownCallback = std::function<void()>;

    /// Register a callback for block tip changes.
    virtual void register_block_tip_callback(BlockTipCallback cb) = 0;

    /// Register a callback for header tip changes.
    virtual void register_header_tip_callback(HeaderTipCallback cb) = 0;

    /// Register a callback for node alerts.
    virtual void register_alert_callback(AlertCallback cb) = 0;

    /// Register a callback for shutdown notification.
    virtual void register_shutdown_callback(ShutdownCallback cb) = 0;

    // ---- Version info ------------------------------------------------------

    /// Get the node software version string.
    virtual std::string get_version_string() = 0;

    /// Get the protocol version number.
    virtual int get_protocol_version() = 0;
};

/// Create a concrete Node implementation wrapping the given node context.
std::unique_ptr<Node> make_node();

/// Create a Node wrapping an existing context (for testing).
std::unique_ptr<Node> make_node(NodeContext& context);

} // namespace flow::interfaces

#endif // FLOWCOIN_INTERFACES_NODE_H
