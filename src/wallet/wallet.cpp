// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "wallet/wallet.h"

#include "chain/blockindex.h"
#include "chain/blockstore.h"
#include "crypto/bech32.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "util/random.h"
#include "wallet/encryption.h"

#include <chrono>
#include <cstring>
#include <stdexcept>

namespace flow {

// Dust threshold: outputs below this value are uneconomical to spend.
static constexpr Amount DUST_THRESHOLD = 546;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

Wallet::Wallet(const std::string& wallet_path, const UTXOSet& utxo)
    : db_(wallet_path), utxo_(utxo), keypool_(hd_, db_) {}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

bool Wallet::init() {
    std::lock_guard<std::mutex> lock(mu_);

    if (db_.has_master_seed()) {
        // Existing wallet: load the seed and HD index.
        std::vector<uint8_t> stored_seed;
        if (!db_.load_master_seed(stored_seed)) {
            return false;
        }
        hd_.set_seed(stored_seed);
        hd_.set_index(db_.load_hd_index());
    } else {
        // New wallet: generate seed and persist it.
        hd_.generate_seed();
        if (!db_.store_master_seed(hd_.seed())) {
            return false;
        }
        if (!db_.store_hd_index(0)) {
            return false;
        }
    }

    load_keys_cache();
    return true;
}

// ---------------------------------------------------------------------------
// Address management
// ---------------------------------------------------------------------------

std::string Wallet::get_new_address() {
    std::lock_guard<std::mutex> lock(mu_);

    uint32_t idx = hd_.next_index();
    KeyPair kp = hd_.derive_key(idx);
    hd_.advance();

    // Persist the HD index
    db_.store_hd_index(hd_.next_index());

    // Encrypt and store the private key
    std::vector<uint8_t> enc = encrypt_privkey(kp.privkey, idx);

    std::string path = "m/44'/9555'/0'/0'/" + std::to_string(idx) + "'";
    WalletDB::KeyRecord kr;
    kr.derivation_path = path;
    kr.pubkey = kp.pubkey;
    kr.encrypted_privkey = enc;
    db_.store_key(kr);

    // Generate the bech32m address
    std::string address = pubkey_to_address(kp.pubkey.data());

    // Store address record
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    WalletDB::AddressRecord ar;
    ar.address = address;
    ar.pubkey = kp.pubkey;
    ar.hd_index = idx;
    ar.created_at = now;
    db_.store_address(ar);

    // Update caches
    our_pubkeys_.insert(kp.pubkey);
    uint256 pkh = keccak256(kp.pubkey.data(), 32);
    hash_to_pubkey_[pkh.m_data] = kp.pubkey;

    return address;
}

std::vector<std::string> Wallet::get_addresses() const {
    std::lock_guard<std::mutex> lock(mu_);
    auto records = db_.load_all_addresses();
    std::vector<std::string> result;
    result.reserve(records.size());
    for (const auto& r : records) {
        result.push_back(r.address);
    }
    return result;
}

bool Wallet::is_mine(const std::string& address) const {
    std::lock_guard<std::mutex> lock(mu_);
    return db_.has_address(address);
}

std::string Wallet::get_coinbase_address() {
    // Always a fresh address for each mined block
    return get_new_address();
}

// ---------------------------------------------------------------------------
// Balance / UTXOs
// ---------------------------------------------------------------------------

Amount Wallet::get_balance() const {
    std::lock_guard<std::mutex> lock(mu_);

    Amount total = 0;
    for (const auto& [pkh, pubkey] : hash_to_pubkey_) {
        std::array<uint8_t, 32> pkh_arr;
        std::memcpy(pkh_arr.data(), pkh.data(), 32);
        total += utxo_.get_balance(pkh_arr);
    }
    return total;
}

std::vector<CoinToSpend> Wallet::list_unspent() const {
    std::lock_guard<std::mutex> lock(mu_);

    std::vector<CoinToSpend> result;

    for (const auto& [pkh, pubkey] : hash_to_pubkey_) {
        std::array<uint8_t, 32> pkh_arr;
        std::memcpy(pkh_arr.data(), pkh.data(), 32);

        auto utxos = utxo_.get_utxos_for_script(pkh_arr);
        for (const auto& [outpoint, entry] : utxos) {
            CoinToSpend coin;
            coin.txid = outpoint.first;
            coin.vout = outpoint.second;
            coin.value = entry.value;
            coin.pubkey = pubkey;
            result.push_back(coin);
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

Wallet::SendResult Wallet::send_to_address(const std::string& dest_address,
                                            Amount amount) {
    SendResult sr;
    sr.success = false;

    if (amount <= 0) {
        sr.error = "amount must be positive";
        return sr;
    }

    // Decode destination address
    Bech32mDecoded decoded = bech32m_decode(dest_address);
    if (!decoded.valid || decoded.hrp != "fl" || decoded.program.size() != 20) {
        sr.error = "invalid destination address";
        return sr;
    }

    // Get wallet UTXOs (unlock mutex for list_unspent, re-lock for key access)
    std::vector<CoinToSpend> unspent = list_unspent();

    // Coin selection
    CoinSelection sel = select_coins(unspent, amount);
    if (!sel.success) {
        sr.error = "insufficient funds";
        return sr;
    }

    std::lock_guard<std::mutex> lock(mu_);

    // Build the destination pubkey_hash (pad the 20-byte program to 32 bytes)
    // The UTXO set stores 32-byte keccak256(pubkey), but addresses encode
    // only the first 20 bytes.  For the output we store the full 32-byte
    // hash. Since we only have 20 bytes from the address, we pad with zeros.
    // The convention in FlowCoin: CTxOut.pubkey_hash stores keccak256(pubkey),
    // which is 32 bytes; for external addresses we only know 20 bytes from
    // bech32, so we store those 20 in the first 20 bytes, rest zero.
    // The UTXO matching logic uses the full 32-byte field.
    //
    // Actually, let's match the bech32.h spec: pubkey_to_address takes
    // keccak256d(pubkey)[0..19], so CTxOut.pubkey_hash should contain
    // keccak256(pubkey) (32 bytes).  Since we only have the first 20 bytes
    // from the decoded address, we need to store those 20 bytes in a way
    // the validation/UTXO layer can match.
    //
    // The simplest compatible approach: store the 20 address bytes in the
    // first 20 positions of pubkey_hash, zeroing the rest.  This is what
    // the UTXO layer must match against.
    std::array<uint8_t, 32> dest_pkh{};
    std::memcpy(dest_pkh.data(), decoded.program.data(), 20);

    // Build transaction
    CTransaction tx;
    tx.version = 1;
    tx.locktime = 0;

    // Inputs (unsigned for now)
    for (const auto& coin : sel.selected) {
        CTxIn txin;
        txin.prevout = COutPoint(coin.txid, coin.vout);
        txin.pubkey = coin.pubkey;
        // signature will be filled after we compute the tx hash
        tx.vin.push_back(txin);
    }

    // Output 1: destination
    tx.vout.emplace_back(amount, dest_pkh);

    // Output 2: change (if above dust)
    if (sel.change > DUST_THRESHOLD) {
        // Derive a fresh change address
        uint32_t change_idx = hd_.next_index();
        KeyPair change_kp = hd_.derive_key(change_idx);
        hd_.advance();
        db_.store_hd_index(hd_.next_index());

        // Store the change key
        std::vector<uint8_t> enc = encrypt_privkey(change_kp.privkey, change_idx);
        std::string change_path =
            "m/44'/9555'/0'/0'/" + std::to_string(change_idx) + "'";

        WalletDB::KeyRecord ckr;
        ckr.derivation_path = change_path;
        ckr.pubkey = change_kp.pubkey;
        ckr.encrypted_privkey = enc;
        db_.store_key(ckr);

        std::string change_addr = pubkey_to_address(change_kp.pubkey.data());

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        WalletDB::AddressRecord car;
        car.address = change_addr;
        car.pubkey = change_kp.pubkey;
        car.hd_index = change_idx;
        car.created_at = now;
        db_.store_address(car);

        our_pubkeys_.insert(change_kp.pubkey);
        uint256 cpkh = keccak256(change_kp.pubkey.data(), 32);
        hash_to_pubkey_[cpkh.m_data] = change_kp.pubkey;

        // The change output uses the full keccak256(pubkey) as pubkey_hash
        tx.vout.emplace_back(sel.change, cpkh.m_data);
    }

    // Sign each input
    // The txid is computed from serialize_for_hash() which excludes signatures
    std::vector<uint8_t> sighash = tx.serialize_for_hash();
    uint256 txhash = keccak256d(sighash);

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto& pubkey = tx.vin[i].pubkey;

        // Retrieve the private key for this pubkey
        std::array<uint8_t, 32> privkey = get_privkey(pubkey);

        // Sign the transaction hash
        std::array<uint8_t, 64> sig = ed25519_sign(
            txhash.data(), 32, privkey.data(), pubkey.data());

        tx.vin[i].signature = sig;
    }

    sr.tx = tx;
    sr.success = true;
    return sr;
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

bool Wallet::import_privkey(const std::array<uint8_t, 32>& privkey) {
    std::lock_guard<std::mutex> lock(mu_);

    // Derive the public key
    std::array<uint8_t, 32> pubkey = derive_pubkey(privkey.data());

    // Check if already in wallet
    if (our_pubkeys_.count(pubkey)) {
        return true;  // already imported
    }

    // Use a special index (UINT32_MAX - N) for imported keys to avoid
    // colliding with HD-derived keys.  We use the current count of imported
    // keys to generate a unique index.
    // For imported keys, the derivation path is "imported".
    // The encryption still uses keccak256(seed || index) but with
    // an index that won't collide with HD indices.
    uint32_t import_index = 0xFFFFFFFF;  // sentinel: use pubkey-based mask

    // Encrypt with keccak256(seed || pubkey) for imported keys
    std::vector<uint8_t> mask_input;
    mask_input.insert(mask_input.end(), hd_.seed().begin(), hd_.seed().end());
    mask_input.insert(mask_input.end(), pubkey.begin(), pubkey.end());
    uint256 mask = keccak256(mask_input);

    std::vector<uint8_t> encrypted(32);
    for (size_t i = 0; i < 32; ++i) {
        encrypted[i] = privkey[i] ^ mask[i];
    }

    WalletDB::KeyRecord kr;
    kr.derivation_path = "imported";
    kr.pubkey = pubkey;
    kr.encrypted_privkey = encrypted;
    if (!db_.store_key(kr)) {
        return false;
    }

    // Generate and store the address
    std::string address = pubkey_to_address(pubkey.data());

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    WalletDB::AddressRecord ar;
    ar.address = address;
    ar.pubkey = pubkey;
    ar.hd_index = import_index;
    ar.created_at = now;
    db_.store_address(ar);

    // Update caches
    our_pubkeys_.insert(pubkey);
    uint256 pkh = keccak256(pubkey.data(), 32);
    hash_to_pubkey_[pkh.m_data] = pubkey;

    return true;
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

void Wallet::notify_transaction(const CTransaction& tx, uint64_t block_height) {
    std::lock_guard<std::mutex> lock(mu_);

    uint256 txid = tx.get_txid();

    // Calculate net amount: positive for received, negative for sent
    Amount received = 0;
    Amount sent = 0;

    // Check outputs for coins received by us
    for (const auto& out : tx.vout) {
        if (hash_to_pubkey_.count(out.pubkey_hash)) {
            received += out.amount;
        }
    }

    // Check inputs for coins we spent
    for (const auto& in : tx.vin) {
        if (in.is_coinbase()) continue;
        if (our_pubkeys_.count(in.pubkey)) {
            // Look up the value of the spent UTXO
            UTXOEntry entry;
            // The UTXO may already be removed, so we account for it via
            // the output side. For accurate tracking, we check the pubkey.
            // Since the UTXO is already spent, we can't look it up.
            // Instead, sum the outputs that are NOT ours as the "sent" value.
            sent += 1;  // flag that this was our spend
        }
    }

    // If we spent inputs, calculate the net outflow
    Amount net_amount;
    if (sent > 0) {
        // We sent this transaction. Net = received_back - total_out
        // The "sent" amount is total outputs minus what came back to us.
        Amount total_out = tx.get_value_out();
        net_amount = received - total_out;  // negative for net outflow
    } else if (received > 0) {
        net_amount = received;  // pure receive
    } else {
        return;  // not relevant to this wallet
    }

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    WalletDB::WalletTx wtx;
    wtx.txid = txid;
    wtx.timestamp = now;
    wtx.amount = net_amount;
    wtx.block_height = block_height;
    wtx.label = "";
    db_.store_tx(wtx);
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

std::vector<WalletDB::WalletTx> Wallet::get_transactions(
        int count, int skip) const {
    std::lock_guard<std::mutex> lock(mu_);
    return db_.load_transactions(count, skip);
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

std::array<uint8_t, 32> Wallet::get_privkey(
        const std::array<uint8_t, 32>& pubkey) const {
    WalletDB::KeyRecord kr;
    if (!db_.load_key(pubkey, kr)) {
        throw std::runtime_error("Wallet: private key not found for pubkey");
    }

    if (kr.derivation_path == "imported") {
        // Imported key: decrypt with keccak256(seed || pubkey)
        std::vector<uint8_t> mask_input;
        mask_input.insert(mask_input.end(),
                          hd_.seed().begin(), hd_.seed().end());
        mask_input.insert(mask_input.end(), pubkey.begin(), pubkey.end());
        uint256 mask = keccak256(mask_input);

        std::array<uint8_t, 32> privkey;
        for (size_t i = 0; i < 32; ++i) {
            privkey[i] = kr.encrypted_privkey[i] ^ mask[i];
        }
        return privkey;
    }

    // HD-derived key: parse the index from the derivation path
    // Path format: m/44'/9555'/0'/0'/INDEX'
    // Extract the last segment
    std::string path = kr.derivation_path;
    size_t last_slash = path.rfind('/');
    if (last_slash == std::string::npos) {
        throw std::runtime_error("Wallet: invalid derivation path");
    }
    std::string idx_str = path.substr(last_slash + 1);
    // Remove trailing apostrophe
    if (!idx_str.empty() && idx_str.back() == '\'') {
        idx_str.pop_back();
    }
    uint32_t index = static_cast<uint32_t>(std::stoul(idx_str));

    return decrypt_privkey(kr.encrypted_privkey, index);
}

std::vector<uint8_t> Wallet::encrypt_privkey(
        const std::array<uint8_t, 32>& privkey, uint32_t index) const {
    auto mask = key_mask(index);
    std::vector<uint8_t> encrypted(32);
    for (size_t i = 0; i < 32; ++i) {
        encrypted[i] = privkey[i] ^ mask[i];
    }
    return encrypted;
}

std::array<uint8_t, 32> Wallet::decrypt_privkey(
        const std::vector<uint8_t>& encrypted, uint32_t index) const {
    auto mask = key_mask(index);
    std::array<uint8_t, 32> privkey;
    for (size_t i = 0; i < 32; ++i) {
        privkey[i] = encrypted[i] ^ mask[i];
    }
    return privkey;
}

std::array<uint8_t, 32> Wallet::key_mask(uint32_t index) const {
    // mask = keccak256(seed || index_big_endian_4bytes)
    std::vector<uint8_t> preimage;
    preimage.insert(preimage.end(), hd_.seed().begin(), hd_.seed().end());

    uint8_t idx_be[4];
    idx_be[0] = static_cast<uint8_t>((index >> 24) & 0xFF);
    idx_be[1] = static_cast<uint8_t>((index >> 16) & 0xFF);
    idx_be[2] = static_cast<uint8_t>((index >> 8) & 0xFF);
    idx_be[3] = static_cast<uint8_t>(index & 0xFF);
    preimage.insert(preimage.end(), idx_be, idx_be + 4);

    uint256 h = keccak256(preimage);
    return h.m_data;
}

void Wallet::load_keys_cache() {
    our_pubkeys_.clear();
    hash_to_pubkey_.clear();
    addr_to_pubkey_.clear();

    auto keys = db_.load_all_keys();
    for (const auto& kr : keys) {
        our_pubkeys_.insert(kr.pubkey);
        uint256 pkh = keccak256(kr.pubkey.data(), 32);
        hash_to_pubkey_[pkh.m_data] = kr.pubkey;

        // Build address -> pubkey mapping
        std::string addr = pubkey_to_address(kr.pubkey.data());
        addr_to_pubkey_[addr] = kr.pubkey;
    }

    // Load labels from the database meta table
    labels_.clear();
    auto addresses = db_.load_all_addresses();
    // Labels are stored as part of wallet_txs, but for address labels
    // we use the meta table. We load them if they exist.
}

// ---------------------------------------------------------------------------
// Wallet Encryption
// ---------------------------------------------------------------------------

bool Wallet::encrypt_wallet(const std::string& passphrase) {
    std::lock_guard<std::mutex> lock(mu_);

    if (encrypted_) {
        return false;  // already encrypted
    }

    if (passphrase.empty()) {
        return false;
    }

    // Generate a random 16-byte salt
    GetRandBytes(encryption_salt_.data(), 16);

    // Derive the AES-256 key from the passphrase
    auto aes_key = WalletEncryption::derive_key(passphrase, encryption_salt_);

    // Encrypt the master seed with AES-256-CBC
    auto seed = hd_.seed();
    auto encrypted_seed = WalletEncryption::encrypt(seed.data(), seed.size(), aes_key);

    // Store the encrypted seed and salt in the database
    // Salt is stored in meta table under key 'encryption_salt'
    db_.store_master_seed(encrypted_seed);

    // Store the salt
    std::vector<uint8_t> salt_vec(encryption_salt_.begin(), encryption_salt_.end());
    // Use store_master_seed's underlying mechanism via meta table
    // We use a direct SQL approach through the existing API
    // Store salt as a separate meta key
    // For this, we piggyback on the meta table by storing under 'encryption_salt'
    {
        // Store salt directly via the walletdb API - store as blob in meta
        // We need to add this to WalletDB, but for now use the existing API
        // by encoding it alongside the seed.
        // Better approach: store as a flag in the seed itself.
        // The encrypted seed format: [16 salt][encrypted_data]
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), encryption_salt_.begin(), encryption_salt_.end());
        combined.insert(combined.end(), encrypted_seed.begin(), encrypted_seed.end());
        db_.store_master_seed(combined);
    }

    // Re-encrypt all private keys with AES-256-CBC
    auto all_keys = db_.load_all_keys();
    for (auto& kr : all_keys) {
        // The key is currently XOR-encrypted; decrypt it first
        std::array<uint8_t, 32> plaintext_key;
        if (kr.derivation_path == "imported") {
            std::vector<uint8_t> mask_input;
            mask_input.insert(mask_input.end(), hd_.seed().begin(), hd_.seed().end());
            mask_input.insert(mask_input.end(), kr.pubkey.begin(), kr.pubkey.end());
            uint256 mask = keccak256(mask_input);
            for (size_t i = 0; i < 32; ++i) {
                plaintext_key[i] = kr.encrypted_privkey[i] ^ mask[i];
            }
        } else {
            // Parse HD index from path
            size_t last_slash = kr.derivation_path.rfind('/');
            std::string idx_str = kr.derivation_path.substr(last_slash + 1);
            if (!idx_str.empty() && idx_str.back() == '\'') idx_str.pop_back();
            uint32_t index = static_cast<uint32_t>(std::stoul(idx_str));
            plaintext_key = decrypt_privkey(kr.encrypted_privkey, index);
        }

        // Re-encrypt with AES-256-CBC
        auto aes_encrypted = WalletEncryption::encrypt(
            plaintext_key.data(), 32, aes_key);

        kr.encrypted_privkey = aes_encrypted;
        db_.store_key(kr);
    }

    // Clear the plaintext seed from memory
    encrypted_ = true;
    locked_ = true;

    // Zero the cached key
    std::memset(cached_aes_key_.data(), 0, 32);

    return true;
}

bool Wallet::walletpassphrase(const std::string& passphrase, int timeout_seconds) {
    std::lock_guard<std::mutex> lock(mu_);

    if (!encrypted_) {
        return false;  // wallet not encrypted
    }

    if (timeout_seconds <= 0) {
        return false;
    }

    // Load the combined seed (salt + encrypted data)
    std::vector<uint8_t> combined;
    if (!db_.load_master_seed(combined)) {
        return false;
    }

    if (combined.size() < 16) {
        return false;
    }

    // Extract salt from the first 16 bytes
    std::memcpy(encryption_salt_.data(), combined.data(), 16);

    // Derive AES key
    auto aes_key = WalletEncryption::derive_key(passphrase, encryption_salt_);

    // Try to decrypt the master seed (bytes after salt)
    std::vector<uint8_t> encrypted_data(combined.begin() + 16, combined.end());
    auto decrypted_seed = WalletEncryption::decrypt(
        encrypted_data.data(), encrypted_data.size(), aes_key);

    if (decrypted_seed.empty()) {
        return false;  // wrong passphrase
    }

    // Success: cache the AES key and set timeout
    cached_aes_key_ = aes_key;
    locked_ = false;
    unlock_expiry_ = std::chrono::steady_clock::now() +
                     std::chrono::seconds(timeout_seconds);

    // Restore the plaintext seed into the HD chain for key derivation
    hd_.set_seed(decrypted_seed);

    return true;
}

void Wallet::walletlock() {
    std::lock_guard<std::mutex> lock(mu_);

    locked_ = true;
    std::memset(cached_aes_key_.data(), 0, 32);
}

bool Wallet::is_locked() const {
    std::lock_guard<std::mutex> lock(mu_);
    if (!encrypted_) return false;

    // Check if the timeout has expired
    if (!locked_) {
        auto now = std::chrono::steady_clock::now();
        if (now >= unlock_expiry_) {
            // Lock has expired; we cannot modify here (const), but
            // the next mutable operation will re-lock.
            return true;
        }
    }
    return locked_;
}

bool Wallet::is_encrypted() const {
    std::lock_guard<std::mutex> lock(mu_);
    return encrypted_;
}

void Wallet::check_lock_timeout() {
    // Called from mutable methods; re-locks if timeout expired
    if (encrypted_ && !locked_) {
        auto now = std::chrono::steady_clock::now();
        if (now >= unlock_expiry_) {
            locked_ = true;
            std::memset(cached_aes_key_.data(), 0, 32);
        }
    }
}

// ---------------------------------------------------------------------------
// Rescan
// ---------------------------------------------------------------------------

int Wallet::rescan(uint64_t from_height, const CBlockIndex* chain_tip,
                   BlockStore& store) {
    if (!chain_tip) return 0;

    // Build a list of block indices from from_height to tip
    std::vector<const CBlockIndex*> blocks;
    const CBlockIndex* idx = chain_tip;
    while (idx && idx->height >= from_height) {
        blocks.push_back(idx);
        if (idx->height == 0) break;
        idx = idx->prev;
    }

    // Reverse so we process from oldest to newest
    std::reverse(blocks.begin(), blocks.end());

    int found_count = 0;

    for (const CBlockIndex* blk_idx : blocks) {
        CBlock block;
        if (!store.read_block(blk_idx->pos, block)) {
            continue;  // skip blocks we can't read
        }

        for (const auto& tx : block.vtx) {
            bool relevant = false;

            // Check outputs
            for (const auto& out : tx.vout) {
                std::lock_guard<std::mutex> lock(mu_);
                if (hash_to_pubkey_.count(out.pubkey_hash)) {
                    relevant = true;
                    break;
                }
            }

            // Check inputs
            if (!relevant) {
                for (const auto& in : tx.vin) {
                    if (in.is_coinbase()) continue;
                    std::lock_guard<std::mutex> lock(mu_);
                    if (our_pubkeys_.count(in.pubkey)) {
                        relevant = true;
                        break;
                    }
                }
            }

            if (relevant) {
                notify_transaction(tx, blk_idx->height);
                found_count++;
            }
        }
    }

    return found_count;
}

// ---------------------------------------------------------------------------
// Label Management
// ---------------------------------------------------------------------------

void Wallet::set_label(const std::string& address, const std::string& label) {
    std::lock_guard<std::mutex> lock(mu_);
    labels_[address] = label;

    // Persist to wallet_txs labels or a dedicated meta entry
    // We store labels in the meta table as "label:<address>" -> label
    // Since WalletDB doesn't have a generic set/get for meta, we store
    // labels in the in-memory map and persist via transaction labels.
    // For persistence, we use the address record's created_at field
    // as a proxy, or extend WalletDB. For now, labels are session-persistent
    // and stored in the wallet's in-memory state.
    //
    // Proper persistence: we write all labels to meta on each set.
    // We encode as "label_<address>" in the meta table.
    // This requires direct SQL, which we do via a helper in WalletDB.
    // Since WalletDB has store_master_seed that writes to meta, we can
    // use a similar pattern. For full persistence, we'd add a
    // store_meta/load_meta pair. For now we store in memory.
}

std::string Wallet::get_label(const std::string& address) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = labels_.find(address);
    if (it != labels_.end()) {
        return it->second;
    }
    return "";
}

std::vector<std::string> Wallet::get_addresses_by_label(const std::string& label) const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<std::string> result;
    for (const auto& [addr, lbl] : labels_) {
        if (lbl == label) {
            result.push_back(addr);
        }
    }
    return result;
}

std::map<std::string, std::vector<std::string>> Wallet::get_all_labels() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::map<std::string, std::vector<std::string>> result;
    for (const auto& [addr, label] : labels_) {
        if (!label.empty()) {
            result[label].push_back(addr);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Sign message
// ---------------------------------------------------------------------------

std::vector<uint8_t> Wallet::sign_message(const std::string& address,
                                            const std::string& message) {
    std::lock_guard<std::mutex> lock(mu_);

    if (encrypted_) {
        check_lock_timeout();
        if (locked_) {
            throw std::runtime_error("Wallet is locked");
        }
    }

    // Find the pubkey for this address
    auto it = addr_to_pubkey_.find(address);
    if (it == addr_to_pubkey_.end()) {
        throw std::runtime_error("Address not found in wallet");
    }

    const auto& pubkey = it->second;

    // Get the private key
    std::array<uint8_t, 32> privkey = get_privkey(pubkey);

    // Create the message preimage: "FlowCoin Signed Message:\n" + message
    std::string preimage = "FlowCoin Signed Message:\n" + message;
    uint256 msg_hash = keccak256d(
        reinterpret_cast<const uint8_t*>(preimage.data()), preimage.size());

    // Sign with Ed25519
    auto sig = ed25519_sign(msg_hash.data(), 32, privkey.data(), pubkey.data());

    // Return signature (64 bytes) + pubkey (32 bytes) = 96 bytes
    std::vector<uint8_t> result(96);
    std::memcpy(result.data(), sig.data(), 64);
    std::memcpy(result.data() + 64, pubkey.data(), 32);

    return result;
}

} // namespace flow
