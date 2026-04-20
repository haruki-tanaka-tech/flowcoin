// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Abstract chain interface for wallet and index subsystems.
// Provides a stable API for querying chain state, submitting
// transactions, and receiving block notifications without
// depending on ChainState internals.

#ifndef FLOWCOIN_INTERFACES_CHAIN_H
#define FLOWCOIN_INTERFACES_CHAIN_H

#include "chain/utxo.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/types.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace flow {
class ChainState;
class Mempool;
}

namespace flow::interfaces {

// ============================================================================
// Chain interface
// ============================================================================

class Chain {
public:
    virtual ~Chain() = default;

    // ---- Block information -------------------------------------------------

    /// Get the height of the active chain tip.
    virtual uint64_t get_height() = 0;

    /// Get the block hash at a specific height.
    /// Returns a null hash if the height is beyond the chain tip.
    virtual uint256 get_block_hash(uint64_t height) = 0;

    /// Get a full block by its hash.
    virtual bool get_block(const uint256& hash, CBlock& block) = 0;

    /// Get a block header by its hash.
    virtual bool get_block_header(const uint256& hash,
                                   CBlockHeader& header) = 0;

    /// Get the block header at a specific height.
    virtual bool get_block_header_at_height(uint64_t height,
                                             CBlockHeader& header) = 0;

    /// Check if a block hash is known (in the block tree).
    virtual bool have_block(const uint256& hash) = 0;

    /// Get the number of confirmations for a block.
    virtual int get_block_confirmations(const uint256& hash) = 0;

    /// Get the timestamp of a block.
    virtual int64_t get_block_time(const uint256& hash) = 0;

    /// Get the height of a block, or -1 if not found.
    virtual int64_t get_block_height(const uint256& hash) = 0;

    // ---- UTXO queries ------------------------------------------------------

    /// Look up a specific UTXO.
    virtual bool get_utxo(const uint256& txid, uint32_t vout,
                           UTXOEntry& entry) = 0;

    /// Check if a UTXO exists.
    virtual bool have_utxo(const uint256& txid, uint32_t vout) = 0;

    /// Get the total number of UTXOs in the set.
    virtual size_t get_utxo_count() = 0;

    /// Get the total value of all UTXOs.
    virtual Amount get_utxo_total_value() = 0;

    // ---- Mempool -----------------------------------------------------------

    /// Check if a transaction is in the mempool.
    virtual bool is_in_mempool(const uint256& txid) = 0;

    /// Submit a transaction to the mempool for relay.
    /// Returns true on acceptance, sets error on failure.
    virtual bool submit_transaction(const CTransaction& tx,
                                     std::string& error) = 0;

    /// Get a transaction from the mempool.
    virtual bool get_mempool_tx(const uint256& txid, CTransaction& tx) = 0;

    /// Get the number of transactions in the mempool.
    virtual size_t get_mempool_size() = 0;

    // ---- Chain state -------------------------------------------------------

    /// Get the adjusted network time.
    virtual int64_t get_adjusted_time() = 0;

    /// Get the next block's difficulty target (nbits).
    virtual uint32_t get_next_nbits() = 0;

    /// Get the minimum relay fee rate (sat/kB).
    virtual Amount get_min_relay_fee() = 0;

    /// Get the median time past (MTP) of the last 11 blocks.
    virtual int64_t get_median_time_past() = 0;

    /// Check if initial block download is in progress.
    virtual bool is_initial_block_download() = 0;

    // ---- Transaction lookup ------------------------------------------------

    /// Find a confirmed transaction by its txid.
    /// Returns false if not found in the transaction index.
    virtual bool find_tx(const uint256& txid, CTransaction& tx,
                          uint256& block_hash, uint64_t& block_height) = 0;

    // ---- Notifications -----------------------------------------------------

    /// Callback for block connect/disconnect events.
    using BlockCallback = std::function<void(
        const CBlock& block, uint64_t height, bool connected)>;

    /// Register a callback for block events.
    virtual void register_block_callback(BlockCallback cb) = 0;

    /// Callback for new transactions (mempool or block).
    using TxCallback = std::function<void(
        const CTransaction& tx, uint64_t height, bool in_block)>;

    /// Register a callback for transaction events.
    virtual void register_tx_callback(TxCallback cb) = 0;

    // ---- Chain lock --------------------------------------------------------

    /// RAII lock for atomic chain state queries.
    class Lock {
    public:
        virtual ~Lock() = default;

        /// Get the tip height while holding the lock.
        virtual uint64_t get_height() = 0;

        /// Get the tip hash while holding the lock.
        virtual uint256 get_tip_hash() = 0;

        /// Get median time past while holding the lock.
        virtual int64_t get_median_time_past() = 0;
    };

    /// Acquire a chain state lock. While the lock is held, the chain
    /// tip cannot change. The lock is released when the returned
    /// object is destroyed.
    virtual std::unique_ptr<Lock> lock() = 0;

    // ---- Chain tips --------------------------------------------------------

    /// Get the current best chain tip hash.
    virtual uint256 get_tip_hash() = 0;

    /// Get the genesis block hash.
    virtual uint256 get_genesis_hash() = 0;
};

/// Create a Chain interface wrapping a ChainState and optional Mempool.
std::unique_ptr<Chain> make_chain(ChainState& chainstate);
std::unique_ptr<Chain> make_chain(ChainState& chainstate, Mempool& mempool);

} // namespace flow::interfaces

#endif // FLOWCOIN_INTERFACES_CHAIN_H
