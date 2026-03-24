// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Transaction primitives for FlowCoin.
//
// Transaction structure mirrors Bitcoin's UTXO model with Ed25519 signatures.
// Each transaction has inputs (references to prior outputs) and outputs
// (amounts locked to public keys).

#ifndef FLOWCOIN_PRIMITIVES_TRANSACTION_H
#define FLOWCOIN_PRIMITIVES_TRANSACTION_H

#include "../util/types.h"

#include <cstdint>
#include <cstring>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// Transaction output point — identifies a specific output of a prior tx
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
};

} // namespace flow

#endif // FLOWCOIN_PRIMITIVES_TRANSACTION_H
