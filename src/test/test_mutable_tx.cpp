// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for mutable transaction handling: CMutableTransaction construction,
// round-trip conversion with CTransaction, signing, fee estimation,
// OP_RETURN outputs, partially signed transactions, PSBT combination,
// and serialization round-trips.

#include "primitives/transaction.h"
#include "consensus/params.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "util/random.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <map>
#include <numeric>
#include <set>
#include <vector>

using namespace flow;

// ---------------------------------------------------------------------------
// CMutableTransaction — a mutable wrapper for building transactions
// ---------------------------------------------------------------------------

class CMutableTransaction {
public:
    uint32_t             version = 1;
    std::vector<CTxIn>   vin;
    std::vector<CTxOut>  vout;
    int64_t              locktime = 0;

    CMutableTransaction() = default;

    explicit CMutableTransaction(const CTransaction& tx)
        : version(tx.version), vin(tx.vin), vout(tx.vout), locktime(tx.locktime) {}

    void add_input(const COutPoint& prevout) {
        CTxIn in;
        in.prevout = prevout;
        vin.push_back(in);
    }

    void add_output(Amount amount, const std::array<uint8_t, 32>& pubkey_hash) {
        CTxOut out(amount, pubkey_hash);
        vout.push_back(out);
    }

    void add_op_return(const std::vector<uint8_t>& data) {
        // OP_RETURN output: amount = 0, pubkey_hash encodes the data hash
        std::array<uint8_t, 32> data_hash{};
        auto h = keccak256(data.data(), data.size());
        std::memcpy(data_hash.data(), h.data(), 32);

        CTxOut out;
        out.amount = 0;
        out.pubkey_hash = data_hash;
        vout.push_back(out);
    }

    CTransaction to_transaction() const {
        CTransaction tx;
        tx.version = version;
        tx.vin = vin;
        tx.vout = vout;
        tx.locktime = locktime;
        return tx;
    }

    bool sign_input(size_t index,
                    const std::array<uint8_t, 32>& privkey,
                    const std::array<uint8_t, 32>& pubkey) {
        if (index >= vin.size()) return false;

        CTransaction tx = to_transaction();
        uint256 sighash = tx.signature_hash(static_cast<uint32_t>(index));

        std::array<uint8_t, 64> sig{};
        if (!ed25519_sign(sig.data(), sighash.data(), 32,
                          privkey.data(), pubkey.data())) {
            return false;
        }

        vin[index].signature = sig;
        vin[index].pubkey = pubkey;
        return true;
    }

    size_t estimated_size() const {
        // 4 (version) + vin.size() * 132 + vout.size() * 40 + 8 (locktime) + compact sizes
        size_t size = 4 + 8;  // version + locktime
        size += 1;  // vin compact size (single byte for < 253 inputs)
        size += vin.size() * 132;  // 36 (outpoint) + 32 (pubkey) + 64 (sig)
        size += 1;  // vout compact size
        size += vout.size() * 40;  // 8 (amount) + 32 (pubkey_hash)
        return size;
    }

    Amount compute_fee(Amount fee_rate) const {
        return static_cast<Amount>(estimated_size()) * fee_rate;
    }
};

// ---------------------------------------------------------------------------
// PartiallySignedTx — PSBT-like structure for multi-party signing
// ---------------------------------------------------------------------------

class PartiallySignedTx {
public:
    CMutableTransaction tx;
    std::vector<bool> signed_inputs;

    explicit PartiallySignedTx(const CMutableTransaction& mtx)
        : tx(mtx), signed_inputs(mtx.vin.size(), false) {}

    bool add_signature(size_t index,
                       const std::array<uint8_t, 64>& sig,
                       const std::array<uint8_t, 32>& pubkey) {
        if (index >= tx.vin.size()) return false;
        tx.vin[index].signature = sig;
        tx.vin[index].pubkey = pubkey;
        signed_inputs[index] = true;
        return true;
    }

    bool is_complete() const {
        for (auto s : signed_inputs) {
            if (!s) return false;
        }
        return !signed_inputs.empty();
    }

    CTransaction finalize() const {
        assert(is_complete());
        return tx.to_transaction();
    }

    bool combine(const PartiallySignedTx& other) {
        if (other.tx.vin.size() != tx.vin.size()) return false;
        for (size_t i = 0; i < signed_inputs.size(); ++i) {
            if (!signed_inputs[i] && other.signed_inputs[i]) {
                tx.vin[i].signature = other.tx.vin[i].signature;
                tx.vin[i].pubkey = other.tx.vin[i].pubkey;
                signed_inputs[i] = true;
            }
        }
        return true;
    }

    std::vector<uint8_t> serialize() const {
        auto tx_data = tx.to_transaction().serialize();
        // Append signed_inputs bitmap
        std::vector<uint8_t> result;
        result.reserve(tx_data.size() + signed_inputs.size() + 4);

        uint32_t tx_len = static_cast<uint32_t>(tx_data.size());
        result.resize(4);
        std::memcpy(result.data(), &tx_len, 4);
        result.insert(result.end(), tx_data.begin(), tx_data.end());

        for (bool s : signed_inputs) {
            result.push_back(s ? 1 : 0);
        }
        return result;
    }

    static PartiallySignedTx deserialize(const std::vector<uint8_t>& data) {
        assert(data.size() >= 4);
        uint32_t tx_len;
        std::memcpy(&tx_len, data.data(), 4);

        assert(data.size() >= 4 + tx_len);
        CTransaction tx;
        tx.deserialize(std::vector<uint8_t>(data.begin() + 4,
                                             data.begin() + 4 + tx_len));

        CMutableTransaction mtx(tx);
        PartiallySignedTx psbt(mtx);

        size_t bitmap_offset = 4 + tx_len;
        for (size_t i = 0; i < psbt.signed_inputs.size() &&
                           bitmap_offset + i < data.size(); ++i) {
            psbt.signed_inputs[i] = (data[bitmap_offset + i] != 0);
        }
        return psbt;
    }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::array<uint8_t, 32> make_test_pkh(uint8_t seed) {
    std::array<uint8_t, 32> pkh{};
    for (int i = 0; i < 32; ++i) pkh[i] = static_cast<uint8_t>(seed + i);
    return pkh;
}

static uint256 make_test_txid(uint8_t seed) {
    uint256 txid;
    for (int i = 0; i < 32; ++i) txid[i] = static_cast<uint8_t>(seed * 3 + i);
    return txid;
}

void test_mutable_tx() {

    // -----------------------------------------------------------------------
    // Test 1: CMutableTransaction: add input/output, convert to CTransaction
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;

        COutPoint prevout(make_test_txid(1), 0);
        mtx.add_input(prevout);

        auto pkh = make_test_pkh(42);
        mtx.add_output(50 * COIN, pkh);

        assert(mtx.vin.size() == 1);
        assert(mtx.vout.size() == 1);
        assert(mtx.vin[0].prevout.txid == make_test_txid(1));
        assert(mtx.vin[0].prevout.index == 0);
        assert(mtx.vout[0].amount == 50 * COIN);

        CTransaction tx = mtx.to_transaction();
        assert(tx.vin.size() == 1);
        assert(tx.vout.size() == 1);
        assert(tx.version == 1);
    }

    // -----------------------------------------------------------------------
    // Test 2: Round-trip: CTransaction -> CMutableTransaction -> CTransaction
    // -----------------------------------------------------------------------
    {
        CTransaction original;
        original.version = 1;

        CTxIn in;
        in.prevout = COutPoint(make_test_txid(5), 2);
        original.vin.push_back(in);

        CTxOut out(10 * COIN, make_test_pkh(77));
        original.vout.push_back(out);

        CMutableTransaction mtx(original);
        CTransaction roundtrip = mtx.to_transaction();

        assert(roundtrip.version == original.version);
        assert(roundtrip.vin.size() == original.vin.size());
        assert(roundtrip.vout.size() == original.vout.size());
        assert(roundtrip.vin[0].prevout == original.vin[0].prevout);
        assert(roundtrip.vout[0].amount == original.vout[0].amount);
        assert(roundtrip.locktime == original.locktime);
    }

    // -----------------------------------------------------------------------
    // Test 3: sign_input produces valid signature
    // -----------------------------------------------------------------------
    {
        // Generate a test keypair
        std::array<uint8_t, 32> privkey{};
        std::array<uint8_t, 32> pubkey{};
        GetRandBytes(privkey.data(), 32);
        ed25519_derive_pubkey(pubkey.data(), privkey.data());

        auto pkh_bytes = keccak256(pubkey.data(), 32);
        std::array<uint8_t, 32> pkh;
        std::memcpy(pkh.data(), pkh_bytes.data(), 32);

        CMutableTransaction mtx;
        mtx.add_input(COutPoint(make_test_txid(10), 0));
        mtx.add_output(1 * COIN, pkh);

        bool signed_ok = mtx.sign_input(0, privkey, pubkey);
        assert(signed_ok);

        // Verify the signature is non-zero
        bool sig_nonzero = false;
        for (auto b : mtx.vin[0].signature) {
            if (b != 0) { sig_nonzero = true; break; }
        }
        assert(sig_nonzero);

        // Verify against the sighash
        CTransaction tx = mtx.to_transaction();
        uint256 sighash = tx.signature_hash(0);
        bool valid = ed25519_verify(mtx.vin[0].signature.data(),
                                     sighash.data(), 32,
                                     pubkey.data());
        assert(valid);
    }

    // -----------------------------------------------------------------------
    // Test 4: estimated_size reasonable
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        mtx.add_input(COutPoint(make_test_txid(1), 0));
        mtx.add_output(1 * COIN, make_test_pkh(1));

        size_t est = mtx.estimated_size();
        // 1 input (132) + 1 output (40) + overhead
        assert(est > 140);
        assert(est < 500);

        // More inputs/outputs -> larger size
        mtx.add_input(COutPoint(make_test_txid(2), 0));
        mtx.add_output(2 * COIN, make_test_pkh(2));
        size_t est2 = mtx.estimated_size();
        assert(est2 > est);
    }

    // -----------------------------------------------------------------------
    // Test 5: compute_fee correct
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        mtx.add_input(COutPoint(make_test_txid(1), 0));
        mtx.add_output(1 * COIN, make_test_pkh(1));

        size_t size = mtx.estimated_size();
        Amount fee_rate = 10;
        Amount fee = mtx.compute_fee(fee_rate);
        assert(fee == static_cast<Amount>(size) * fee_rate);
        assert(fee > 0);
    }

    // -----------------------------------------------------------------------
    // Test 6: add_op_return with data
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        mtx.add_input(COutPoint(make_test_txid(1), 0));

        std::vector<uint8_t> op_return_data = {0xDE, 0xAD, 0xBE, 0xEF};
        mtx.add_op_return(op_return_data);

        assert(mtx.vout.size() == 1);
        assert(mtx.vout[0].amount == 0);

        // The pubkey_hash should be the keccak256 of the data
        auto expected_hash = keccak256(op_return_data.data(), op_return_data.size());
        assert(std::memcmp(mtx.vout[0].pubkey_hash.data(),
                           expected_hash.data(), 32) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 7: PartiallySignedTx: add signatures one at a time
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        mtx.add_input(COutPoint(make_test_txid(1), 0));
        mtx.add_input(COutPoint(make_test_txid(2), 1));
        mtx.add_output(5 * COIN, make_test_pkh(50));

        PartiallySignedTx psbt(mtx);
        assert(!psbt.is_complete());

        std::array<uint8_t, 64> sig1{};
        std::array<uint8_t, 32> pk1{};
        sig1[0] = 0x01;
        pk1[0] = 0x01;

        assert(psbt.add_signature(0, sig1, pk1));
        assert(!psbt.is_complete());

        std::array<uint8_t, 64> sig2{};
        std::array<uint8_t, 32> pk2{};
        sig2[0] = 0x02;
        pk2[0] = 0x02;

        assert(psbt.add_signature(1, sig2, pk2));
        assert(psbt.is_complete());
    }

    // -----------------------------------------------------------------------
    // Test 8: PartiallySignedTx: is_complete() false until all signed
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        for (int i = 0; i < 5; ++i) {
            mtx.add_input(COutPoint(make_test_txid(static_cast<uint8_t>(i)), 0));
        }
        mtx.add_output(1 * COIN, make_test_pkh(99));

        PartiallySignedTx psbt(mtx);

        for (int i = 0; i < 5; ++i) {
            assert(!psbt.is_complete());
            std::array<uint8_t, 64> sig{};
            std::array<uint8_t, 32> pk{};
            sig[0] = static_cast<uint8_t>(i + 1);
            pk[0] = static_cast<uint8_t>(i + 1);
            psbt.add_signature(static_cast<size_t>(i), sig, pk);
        }
        assert(psbt.is_complete());
    }

    // -----------------------------------------------------------------------
    // Test 9: PartiallySignedTx: finalize() produces valid tx
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        mtx.add_input(COutPoint(make_test_txid(1), 0));
        mtx.add_output(1 * COIN, make_test_pkh(1));

        PartiallySignedTx psbt(mtx);
        std::array<uint8_t, 64> sig{};
        std::array<uint8_t, 32> pk{};
        sig[0] = 0xFF;
        pk[0] = 0xAA;

        psbt.add_signature(0, sig, pk);
        assert(psbt.is_complete());

        CTransaction final_tx = psbt.finalize();
        assert(final_tx.vin.size() == 1);
        assert(final_tx.vout.size() == 1);
        assert(final_tx.vin[0].signature[0] == 0xFF);
        assert(final_tx.vin[0].pubkey[0] == 0xAA);
    }

    // -----------------------------------------------------------------------
    // Test 10: PartiallySignedTx: combine two partial PSBTs
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        mtx.add_input(COutPoint(make_test_txid(1), 0));
        mtx.add_input(COutPoint(make_test_txid(2), 0));
        mtx.add_output(3 * COIN, make_test_pkh(33));

        // Party A signs input 0
        PartiallySignedTx psbt_a(mtx);
        std::array<uint8_t, 64> sig_a{};
        std::array<uint8_t, 32> pk_a{};
        sig_a[0] = 0x0A;
        pk_a[0] = 0x0A;
        psbt_a.add_signature(0, sig_a, pk_a);

        // Party B signs input 1
        PartiallySignedTx psbt_b(mtx);
        std::array<uint8_t, 64> sig_b{};
        std::array<uint8_t, 32> pk_b{};
        sig_b[0] = 0x0B;
        pk_b[0] = 0x0B;
        psbt_b.add_signature(1, sig_b, pk_b);

        // Combine
        assert(psbt_a.combine(psbt_b));
        assert(psbt_a.is_complete());

        CTransaction final_tx = psbt_a.finalize();
        assert(final_tx.vin[0].signature[0] == 0x0A);
        assert(final_tx.vin[1].signature[0] == 0x0B);
    }

    // -----------------------------------------------------------------------
    // Test 11: PartiallySignedTx: serialize/deserialize round-trip
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        mtx.add_input(COutPoint(make_test_txid(7), 3));
        mtx.add_output(2 * COIN, make_test_pkh(77));

        PartiallySignedTx psbt(mtx);
        std::array<uint8_t, 64> sig{};
        std::array<uint8_t, 32> pk{};
        sig[0] = 0xCC;
        pk[0] = 0xDD;
        psbt.add_signature(0, sig, pk);

        auto serialized = psbt.serialize();
        assert(!serialized.empty());

        auto psbt2 = PartiallySignedTx::deserialize(serialized);
        assert(psbt2.is_complete() == psbt.is_complete());
        assert(psbt2.tx.vin.size() == psbt.tx.vin.size());
        assert(psbt2.tx.vout.size() == psbt.tx.vout.size());
    }

    // -----------------------------------------------------------------------
    // Test 12: Multiple outputs with different amounts
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        mtx.add_input(COutPoint(make_test_txid(1), 0));

        for (int i = 1; i <= 10; ++i) {
            mtx.add_output(static_cast<Amount>(i) * COIN,
                           make_test_pkh(static_cast<uint8_t>(i)));
        }

        assert(mtx.vout.size() == 10);

        CTransaction tx = mtx.to_transaction();
        Amount total = tx.get_value_out();
        assert(total == 55 * COIN);  // 1+2+...+10 = 55
    }

    // -----------------------------------------------------------------------
    // Test 13: Sign fails for out-of-range input index
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        mtx.add_input(COutPoint(make_test_txid(1), 0));
        mtx.add_output(1 * COIN, make_test_pkh(1));

        std::array<uint8_t, 32> privkey{}, pubkey{};
        bool result = mtx.sign_input(5, privkey, pubkey);  // index 5, only 1 input
        assert(!result);
    }

    // -----------------------------------------------------------------------
    // Test 14: Empty PSBT is not complete
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        // No inputs, no outputs
        PartiallySignedTx psbt(mtx);
        assert(!psbt.is_complete());
    }

    // -----------------------------------------------------------------------
    // Test 15: Combine with mismatched input count fails
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx1;
        mtx1.add_input(COutPoint(make_test_txid(1), 0));
        mtx1.add_output(1 * COIN, make_test_pkh(1));

        CMutableTransaction mtx2;
        mtx2.add_input(COutPoint(make_test_txid(1), 0));
        mtx2.add_input(COutPoint(make_test_txid(2), 0));
        mtx2.add_output(1 * COIN, make_test_pkh(1));

        PartiallySignedTx psbt1(mtx1);
        PartiallySignedTx psbt2(mtx2);

        assert(!psbt1.combine(psbt2));
    }

    // -----------------------------------------------------------------------
    // Test 16: Version field preserved through round-trip
    // -----------------------------------------------------------------------
    {
        CMutableTransaction mtx;
        mtx.version = 2;
        mtx.locktime = 500000;
        mtx.add_input(COutPoint(make_test_txid(1), 0));
        mtx.add_output(1 * COIN, make_test_pkh(1));

        CTransaction tx = mtx.to_transaction();
        CMutableTransaction mtx2(tx);

        assert(mtx2.version == 2);
        assert(mtx2.locktime == 500000);
    }
}
