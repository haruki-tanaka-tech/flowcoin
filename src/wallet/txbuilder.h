// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Transaction builder: constructs, sizes, and signs FlowCoin transactions.
// Separated from the wallet to allow programmatic transaction construction
// without wallet key access (e.g., for RPC createrawtransaction).

#pragma once

#include "primitives/transaction.h"
#include "util/types.h"

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace flow {

class TxBuilder {
public:
    /// Add an input (UTXO to spend).
    /// @param txid   Transaction ID of the UTXO.
    /// @param vout   Output index within that transaction.
    /// @param value  Amount held by the UTXO (atomic units).
    /// @param pubkey Ed25519 public key that owns the UTXO.
    /// @return       Reference to this builder for chaining.
    TxBuilder& add_input(const uint256& txid, uint32_t vout,
                          Amount value, const std::array<uint8_t, 32>& pubkey);

    /// Add an output (destination).
    /// @param pubkey_hash  Recipient's pubkey hash (keccak256(pubkey), 32 bytes).
    /// @param value        Amount to send (atomic units).
    /// @return             Reference to this builder for chaining.
    TxBuilder& add_output(const std::vector<uint8_t>& pubkey_hash, Amount value);

    /// Convenience overload: add output from a 32-byte array.
    TxBuilder& add_output(const std::array<uint8_t, 32>& pubkey_hash, Amount value);

    /// Set the change address (pubkey hash).
    /// If change is above the dust threshold, an extra output is added.
    /// @param change_pubkey_hash  32-byte pubkey hash for the change output.
    /// @return                    Reference to this builder for chaining.
    TxBuilder& set_change_address(const std::vector<uint8_t>& change_pubkey_hash);

    /// Set the fee rate in atomic units per byte.
    /// @param fee_rate  Fee rate (default is 1).
    /// @return          Reference to this builder for chaining.
    TxBuilder& set_fee_rate(Amount fee_rate);

    /// Result of building a transaction.
    struct BuildResult {
        CTransaction tx;
        Amount fee;
        Amount change;
        bool success;
        std::string error;
    };

    /// Build the transaction. Computes fees from the estimated size, adds a
    /// change output if the remainder exceeds the dust threshold.
    /// Does NOT sign the inputs (signatures are zeroed).
    /// @return  BuildResult with the unsigned transaction or an error.
    BuildResult build() const;

    /// Signing callback type.
    /// Given a transaction hash and the public key of the input to sign,
    /// returns the 64-byte Ed25519 signature.
    using SignFunc = std::function<std::array<uint8_t, 64>(
        const uint256& tx_hash, const std::array<uint8_t, 32>& pubkey)>;

    /// Sign all inputs of a built transaction using the provided callback.
    /// The callback is invoked once per input with the transaction's signing
    /// hash and the input's public key.
    /// @param tx         The transaction to sign (modified in-place).
    /// @param sign_func  Callback that produces Ed25519 signatures.
    /// @return           true if all inputs were signed successfully.
    bool sign(CTransaction& tx, SignFunc sign_func) const;

    /// Reset the builder to its initial state.
    void clear();

    /// Return the number of inputs currently added.
    size_t input_count() const { return inputs_.size(); }

    /// Return the number of explicit outputs currently added.
    size_t output_count() const { return outputs_.size(); }

    /// Return the total value of all inputs.
    Amount total_input_value() const;

    /// Return the total value of all explicit outputs.
    Amount total_output_value() const;

    /// Dust threshold: outputs below this value are uneconomical to spend.
    static constexpr Amount DUST_THRESHOLD = 546;

private:
    struct InputInfo {
        uint256 txid;
        uint32_t vout;
        Amount value;
        std::array<uint8_t, 32> pubkey;
    };

    struct OutputInfo {
        std::array<uint8_t, 32> pubkey_hash;
        Amount value;
    };

    std::vector<InputInfo> inputs_;
    std::vector<OutputInfo> outputs_;
    std::array<uint8_t, 32> change_pubkey_hash_{};
    bool has_change_address_ = false;
    Amount fee_rate_ = 1;  // default 1 atomic unit per byte

    /// Estimate the serialized transaction size in bytes.
    /// Includes space for signatures (64 bytes per input).
    size_t estimate_size() const;

    /// Estimate size with an additional change output.
    size_t estimate_size_with_change() const;
};

} // namespace flow
