// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Transaction primitives for FlowCoin.
//
// Transaction structure mirrors Bitcoin's UTXO model with Ed25519 signatures.
// Each transaction has inputs (references to prior outputs) and outputs
// (amounts locked to public keys).
//
// Serialized transaction format:
//   version      (4 bytes, LE)
//   vin_count    (CompactSize)
//   vin[]        for each input:
//     txid       (32 bytes)
//     index      (4 bytes, LE)
//     pubkey     (32 bytes)
//     signature  (64 bytes)
//   vout_count   (CompactSize)
//   vout[]       for each output:
//     amount     (8 bytes, LE signed)
//     pubkey_hash (32 bytes)
//   locktime     (8 bytes, LE signed)
//
// For txid computation (serialize_for_hash), signatures are omitted.

#ifndef FLOWCOIN_PRIMITIVES_TRANSACTION_H
#define FLOWCOIN_PRIMITIVES_TRANSACTION_H

#include "../util/types.h"

#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// Transaction constants
// ---------------------------------------------------------------------------

/// Maximum serialized transaction size (1 MB).
static constexpr size_t MAX_TX_SIZE = 1'000'000;

/// Maximum number of inputs per transaction.
static constexpr size_t MAX_TX_INPUTS = 10000;

/// Maximum number of outputs per transaction.
static constexpr size_t MAX_TX_OUTPUTS = 10000;

/// Maximum value for a single output (21M coins in atomic units).
static constexpr Amount MAX_MONEY = 21'000'000LL * 100'000'000LL;

/// Dust threshold: outputs below this amount are considered dust
/// and rejected by the mempool (not consensus).
static constexpr Amount DUST_THRESHOLD = 546;

// ---------------------------------------------------------------------------
// Transaction output point -- identifies a specific output of a prior tx
// ---------------------------------------------------------------------------

struct COutPoint {
    uint256  txid;    //!< Transaction hash
    uint32_t index;   //!< Output index within that transaction

    COutPoint() : index(0) {}
    COutPoint(const uint256& txid_in, uint32_t index_in)
        : txid(txid_in), index(index_in) {}

    bool is_null() const { return txid.is_null() && index == 0; }

    bool operator==(const COutPoint& o) const {
        return txid == o.txid && index == o.index;
    }
    bool operator!=(const COutPoint& o) const { return !(*this == o); }

    bool operator<(const COutPoint& o) const {
        if (txid < o.txid) return true;
        if (o.txid < txid) return false;
        return index < o.index;
    }

    bool operator<=(const COutPoint& o) const {
        return *this == o || *this < o;
    }

    bool operator>(const COutPoint& o) const {
        return o < *this;
    }

    bool operator>=(const COutPoint& o) const {
        return o <= *this;
    }

    /// Serialize to bytes (36 bytes: 32-byte txid + 4-byte index LE).
    std::vector<uint8_t> serialize() const;

    /// Deserialize from bytes.
    bool deserialize(const uint8_t* data, size_t len);

    /// Get a string representation for debugging.
    std::string to_string() const;
};

/// Hash function for COutPoint (for use in unordered containers).
struct COutPointHash {
    size_t operator()(const COutPoint& outpoint) const {
        // Use first 8 bytes of txid XOR'd with index
        uint64_t h = 0;
        std::memcpy(&h, outpoint.txid.data(), 8);
        return static_cast<size_t>(h ^ outpoint.index);
    }
};

// ---------------------------------------------------------------------------
// Transaction input
// ---------------------------------------------------------------------------

struct CTxIn {
    COutPoint prevout;                        //!< Previous output being spent
    std::array<uint8_t, 64> signature{};      //!< Ed25519 signature over the tx hash
    std::array<uint8_t, 32> pubkey{};         //!< Signer's Ed25519 public key

    CTxIn() = default;
    CTxIn(const COutPoint& prevout_in,
          const std::array<uint8_t, 64>& sig,
          const std::array<uint8_t, 32>& pk)
        : prevout(prevout_in), signature(sig), pubkey(pk) {}

    /** A coinbase input has a null prevout. */
    bool is_coinbase() const { return prevout.is_null(); }

    /** Get the serialized size of this input (132 bytes: 36 + 32 + 64). */
    size_t get_serialize_size() const { return 36 + 32 + 64; }

    /** Serialize this input to bytes. */
    std::vector<uint8_t> serialize() const;

    /** Serialize this input without signature (for txid computation). */
    std::vector<uint8_t> serialize_for_hash() const;
};

// ---------------------------------------------------------------------------
// Transaction output
// ---------------------------------------------------------------------------

struct CTxOut {
    Amount amount;                            //!< Value in atomic units
    std::array<uint8_t, 32> pubkey_hash{};    //!< Recipient: keccak256(pubkey)[0..32]

    CTxOut() : amount(0) {}
    CTxOut(Amount amount_in, const std::array<uint8_t, 32>& pkh)
        : amount(amount_in), pubkey_hash(pkh) {}

    bool is_null() const { return amount == 0; }

    /** Check if this output is dust (below the dust threshold). */
    bool is_dust() const { return amount > 0 && amount < DUST_THRESHOLD; }

    /** Get the serialized size (40 bytes: 8 + 32). */
    size_t get_serialize_size() const { return 8 + 32; }

    /** Serialize this output to bytes. */
    std::vector<uint8_t> serialize() const;

    /** Get a string representation for debugging. */
    std::string to_string() const;
};

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

class CTransaction {
public:
    uint32_t             version;    //!< Transaction format version (currently 1)
    std::vector<CTxIn>   vin;        //!< Inputs
    std::vector<CTxOut>  vout;       //!< Outputs
    int64_t              locktime;   //!< Locktime (0 = no lock)

    CTransaction() : version(1), locktime(0) {}

    /** Compute the transaction ID (double keccak256 of serialized tx data). */
    uint256 get_txid() const;

    /** Serialize the transaction for hashing (excludes signatures for txid). */
    std::vector<uint8_t> serialize_for_hash() const;

    /** Full serialization (including signatures). */
    std::vector<uint8_t> serialize() const;

    /** Deserialize from a byte buffer.
     *  @param data  Input buffer.
     *  @param len   Length of input buffer.
     *  @param consumed  Output: number of bytes consumed.
     *  @return true on success. */
    bool deserialize(const uint8_t* data, size_t len, size_t& consumed);

    /** Deserialize from a byte vector. */
    bool deserialize(const std::vector<uint8_t>& data);

    /** Is this a coinbase transaction? (exactly one input, which is null) */
    bool is_coinbase() const {
        return vin.size() == 1 && vin[0].is_coinbase();
    }

    /** Sum of all output amounts. */
    Amount get_value_out() const {
        Amount total = 0;
        for (const auto& out : vout) {
            total += out.amount;
        }
        return total;
    }

    /** Get total input value using a UTXO lookup function.
     *  The lookup function takes an outpoint and returns the amount,
     *  or -1 if the UTXO is not found.
     *  For coinbase transactions, returns 0 (no inputs to look up). */
    Amount get_value_in(std::function<Amount(const COutPoint&)> utxo_lookup) const;

    /** Check if the transaction is final given the block height and time.
     *  A transaction is final if:
     *  - locktime == 0, or
     *  - locktime < 500,000,000 and locktime < height, or
     *  - locktime >= 500,000,000 and locktime < time */
    bool is_final(uint64_t height, int64_t time) const;

    /** Basic validity checks (no context needed):
     *  - Non-empty vin and vout
     *  - Output values are non-negative and don't exceed MAX_MONEY
     *  - Total output value doesn't exceed MAX_MONEY
     *  - No duplicate inputs
     *  - Serialized size within limits */
    bool check_transaction() const;

    /** Compute the signature hash for a specific input.
     *  This is the hash that the Ed25519 signature must sign over.
     *  sighash = keccak256d(serialize_for_hash() || input_index as LE32)
     *  @param input_index  Index of the input being signed.
     *  @return The 32-byte signature hash. */
    uint256 signature_hash(uint32_t input_index) const;

    /** Get the pre-computed serialized size without actually serializing.
     *  Useful for size limit checks before serialization. */
    size_t get_serialize_size() const;

    /** Get a string representation for debugging. */
    std::string to_string() const;

    /** Check if this transaction has any witness data (reserved for future). */
    bool has_witness() const { return false; }

    /** Compute the virtual size (for fee calculation).
     *  Currently equal to serialized size since we have no witness discount
     *  on regular transaction data. */
    size_t get_virtual_size() const { return get_serialize_size(); }

    /** Compare two transactions by txid. */
    bool operator==(const CTransaction& other) const {
        return get_txid() == other.get_txid();
    }
    bool operator!=(const CTransaction& other) const {
        return !(*this == other);
    }

    // ═══ Transaction analysis ═══

    struct TxAnalysis {
        uint256 txid;
        bool is_coinbase;
        size_t serialized_size;
        size_t weight;
        int input_count;
        int output_count;
        Amount total_input;
        Amount total_output;
        Amount fee;
        double fee_rate;
        int sigops;
        bool is_standard;
        std::string type;
        bool is_rbf;
        bool is_final;
    };

    TxAnalysis analyze(const std::function<Amount(const COutPoint&)>& utxo_lookup = nullptr) const;
};

// ═══════════════════════════════════════════════════════════════════════════
// CMutableTransaction — modifiable transaction for building
// ═══════════════════════════════════════════════════════════════════════════

class CMutableTransaction {
public:
    int32_t version = 1;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    int64_t locktime = 0;

    CTransaction to_tx() const;
    static CMutableTransaction from_tx(const CTransaction& tx);

    void add_input(const uint256& txid, uint32_t vout);
    void add_output(const std::vector<uint8_t>& pubkey_hash, Amount value);
    void add_op_return(const std::vector<uint8_t>& data);

    bool sign_input(uint32_t index, const uint8_t* privkey,
                    const uint8_t* pubkey, const uint256& prevout_hash);

    size_t estimated_size() const;
    Amount compute_fee(const std::vector<Amount>& input_values) const;
};

// ═══════════════════════════════════════════════════════════════════════════
// PartiallySignedTx — PSBT-like partially signed transaction
// ═══════════════════════════════════════════════════════════════════════════

class PartiallySignedTx {
public:
    CMutableTransaction tx;

    struct InputInfo {
        bool signed_ = false;
        std::array<uint8_t, 64> signature{};
        std::array<uint8_t, 32> pubkey{};
        Amount value = 0;
        uint256 prev_txid;
        uint32_t prev_vout = 0;
    };
    std::vector<InputInfo> inputs;

    bool add_signature(uint32_t index, const std::array<uint8_t, 64>& sig,
                       const std::array<uint8_t, 32>& pubkey);
    bool is_complete() const;
    CTransaction finalize() const;
    static PartiallySignedTx combine(const PartiallySignedTx& a,
                                      const PartiallySignedTx& b);
    std::vector<uint8_t> serialize() const;
    static PartiallySignedTx deserialize(const std::vector<uint8_t>& data);
};

// ---------------------------------------------------------------------------
// Signature hash computation helper
// ---------------------------------------------------------------------------

/// Compute the signature hash for a given transaction and input index.
/// This is the hash that the Ed25519 signature for input_index must sign over.
uint256 SignatureHash(const CTransaction& tx, uint32_t input_index);

} // namespace flow

#endif // FLOWCOIN_PRIMITIVES_TRANSACTION_H
