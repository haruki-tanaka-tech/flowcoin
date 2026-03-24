// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "chain/blockstore.h"
#include "consensus/params.h"
#include "util/serialize.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>

namespace flow {

// ---------------------------------------------------------------------------
// Helpers: block serialization to/from raw bytes
// ---------------------------------------------------------------------------

static void serialize_header(DataWriter& w, const CBlockHeader& hdr) {
    w.write_bytes(hdr.prev_hash.data(), 32);
    w.write_bytes(hdr.merkle_root.data(), 32);
    w.write_bytes(hdr.training_hash.data(), 32);
    w.write_bytes(hdr.dataset_hash.data(), 32);
    w.write_u64_le(hdr.height);
    w.write_i64_le(hdr.timestamp);
    w.write_u32_le(hdr.nbits);
    w.write_float_le(hdr.val_loss);
    w.write_float_le(hdr.prev_val_loss);
    w.write_u32_le(hdr.d_model);
    w.write_u32_le(hdr.n_layers);
    w.write_u32_le(hdr.d_ff);
    w.write_u32_le(hdr.n_heads);
    w.write_u32_le(hdr.gru_dim);
    w.write_u32_le(hdr.n_slots);
    w.write_u32_le(hdr.train_steps);
    w.write_u32_le(hdr.stagnation);
    w.write_u32_le(hdr.delta_offset);
    w.write_u32_le(hdr.delta_length);
    w.write_u32_le(hdr.sparse_count);
    w.write_float_le(hdr.sparse_threshold);
    w.write_u32_le(hdr.nonce);
    w.write_u32_le(hdr.version);
    w.write_bytes(hdr.miner_pubkey.data(), 32);
    w.write_bytes(hdr.miner_sig.data(), 64);
}

static bool deserialize_header(DataReader& r, CBlockHeader& hdr) {
    auto prev = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(hdr.prev_hash.data(), prev.data(), 32);

    auto mroot = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(hdr.merkle_root.data(), mroot.data(), 32);

    auto thash = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(hdr.training_hash.data(), thash.data(), 32);

    auto dhash = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(hdr.dataset_hash.data(), dhash.data(), 32);

    hdr.height          = r.read_u64_le();
    hdr.timestamp       = r.read_i64_le();
    hdr.nbits           = r.read_u32_le();
    hdr.val_loss        = r.read_float_le();
    hdr.prev_val_loss   = r.read_float_le();
    hdr.d_model         = r.read_u32_le();
    hdr.n_layers        = r.read_u32_le();
    hdr.d_ff            = r.read_u32_le();
    hdr.n_heads         = r.read_u32_le();
    hdr.gru_dim         = r.read_u32_le();
    hdr.n_slots         = r.read_u32_le();
    hdr.train_steps     = r.read_u32_le();
    hdr.stagnation      = r.read_u32_le();
    hdr.delta_offset    = r.read_u32_le();
    hdr.delta_length    = r.read_u32_le();
    hdr.sparse_count    = r.read_u32_le();
    hdr.sparse_threshold = r.read_float_le();
    hdr.nonce           = r.read_u32_le();
    hdr.version         = r.read_u32_le();

    auto pubkey = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(hdr.miner_pubkey.data(), pubkey.data(), 32);

    auto sig = r.read_bytes(64);
    if (r.error()) return false;
    std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

    return !r.error();
}

static void serialize_tx(DataWriter& w, const CTransaction& tx) {
    w.write_u32_le(tx.version);

    w.write_compact_size(tx.vin.size());
    for (const auto& in : tx.vin) {
        w.write_bytes(in.prevout.txid.data(), 32);
        w.write_u32_le(in.prevout.index);
        w.write_bytes(in.pubkey.data(), 32);
        w.write_bytes(in.signature.data(), 64);
    }

    w.write_compact_size(tx.vout.size());
    for (const auto& out : tx.vout) {
        w.write_i64_le(out.amount);
        w.write_bytes(out.pubkey_hash.data(), 32);
    }

    w.write_i64_le(tx.locktime);
}

static bool deserialize_tx(DataReader& r, CTransaction& tx) {
    tx.version = r.read_u32_le();
    if (r.error()) return false;

    uint64_t nin = r.read_compact_size();
    if (r.error() || nin > 100'000) return false;
    tx.vin.resize(static_cast<size_t>(nin));

    for (auto& in : tx.vin) {
        auto txid_bytes = r.read_bytes(32);
        if (r.error()) return false;
        std::memcpy(in.prevout.txid.data(), txid_bytes.data(), 32);
        in.prevout.index = r.read_u32_le();

        auto pk = r.read_bytes(32);
        if (r.error()) return false;
        std::memcpy(in.pubkey.data(), pk.data(), 32);

        auto sig = r.read_bytes(64);
        if (r.error()) return false;
        std::memcpy(in.signature.data(), sig.data(), 64);
    }

    uint64_t nout = r.read_compact_size();
    if (r.error() || nout > 100'000) return false;
    tx.vout.resize(static_cast<size_t>(nout));

    for (auto& out : tx.vout) {
        out.amount = r.read_i64_le();
        auto pkh = r.read_bytes(32);
        if (r.error()) return false;
        std::memcpy(out.pubkey_hash.data(), pkh.data(), 32);
    }

    tx.locktime = r.read_i64_le();
    return !r.error();
}

// ---------------------------------------------------------------------------
// BlockStore constructor
// ---------------------------------------------------------------------------

BlockStore::BlockStore(const std::string& datadir)
    : datadir_(datadir)
{
    // Ensure the blocks/ subdirectory exists
    std::string blocks_dir = datadir_ + "/blocks";
    ::mkdir(blocks_dir.c_str(), 0755);

    // Scan existing blk files to determine current file and offset.
    // Start from file 0 and find the last one that exists.
    current_file_ = 0;
    current_offset_ = 0;

    while (true) {
        std::string path = get_block_path(current_file_);
        FILE* f = std::fopen(path.c_str(), "rb");
        if (!f) {
            // File doesn't exist. If this is file 0, we'll create it on first write.
            // If > 0, the previous file was the last one.
            break;
        }

        // Get file size to know where we left off
        std::fseek(f, 0, SEEK_END);
        long fsize = std::ftell(f);
        std::fclose(f);

        if (fsize < 0) {
            break;
        }

        uint32_t file_size = static_cast<uint32_t>(fsize);

        if (file_size >= MAX_FILE_SIZE) {
            // This file is full, move to the next
            current_file_++;
            current_offset_ = 0;
        } else {
            // This is the current file; continue appending
            current_offset_ = file_size;
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// get_block_path
// ---------------------------------------------------------------------------

std::string BlockStore::get_block_path(int file_num) const {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "blk%05d.dat", file_num);
    return datadir_ + "/blocks/" + buf;
}

// ---------------------------------------------------------------------------
// serialize_block
// ---------------------------------------------------------------------------

std::vector<uint8_t> BlockStore::serialize_block(const CBlock& block) const {
    DataWriter w(4096);

    // Serialize header (308 bytes fixed)
    serialize_header(w, block);

    // Serialize transaction count + transactions
    w.write_compact_size(block.vtx.size());
    for (const auto& tx : block.vtx) {
        serialize_tx(w, tx);
    }

    // Serialize delta payload
    w.write_compact_size(block.delta_payload.size());
    if (!block.delta_payload.empty()) {
        w.write_bytes(block.delta_payload.data(), block.delta_payload.size());
    }

    return w.release();
}

// ---------------------------------------------------------------------------
// deserialize_block
// ---------------------------------------------------------------------------

bool BlockStore::deserialize_block(const uint8_t* data, size_t len, CBlock& block) const {
    DataReader r(data, len);

    // Deserialize header
    if (!deserialize_header(r, block)) return false;

    // Deserialize transactions
    uint64_t ntx = r.read_compact_size();
    if (r.error() || ntx > 100'000) return false;
    block.vtx.resize(static_cast<size_t>(ntx));
    for (auto& tx : block.vtx) {
        if (!deserialize_tx(r, tx)) return false;
    }

    // Deserialize delta payload
    uint64_t delta_len = r.read_compact_size();
    if (r.error() || delta_len > consensus::MAX_DELTA_SIZE) return false;
    if (delta_len > 0) {
        block.delta_payload = r.read_bytes(static_cast<size_t>(delta_len));
        if (r.error()) return false;
    } else {
        block.delta_payload.clear();
    }

    return true;
}

// ---------------------------------------------------------------------------
// write_block
// ---------------------------------------------------------------------------

BlockPos BlockStore::write_block(const CBlock& block) {
    // Serialize the block
    std::vector<uint8_t> block_data = serialize_block(block);
    uint32_t block_size = static_cast<uint32_t>(block_data.size());

    // Check if we need to roll to a new file.
    // Each entry is: 4 (magic) + 4 (size) + block_size
    uint32_t entry_size = 8 + block_size;
    if (current_offset_ > 0 &&
        static_cast<size_t>(current_offset_) + entry_size > MAX_FILE_SIZE) {
        current_file_++;
        current_offset_ = 0;
    }

    // Record position before writing
    BlockPos pos;
    pos.file_num = current_file_;
    pos.offset   = current_offset_;
    pos.size     = block_size;

    // Open file for appending
    std::string path = get_block_path(current_file_);
    FILE* f = std::fopen(path.c_str(), "ab");
    if (!f) {
        fprintf(stderr, "BlockStore: failed to open %s for writing: %s\n",
                path.c_str(), std::strerror(errno));
        return BlockPos{};  // null pos indicates failure
    }

    // Write magic bytes (MAINNET_MAGIC, big-endian as 4 bytes)
    uint32_t magic = consensus::MAINNET_MAGIC;
    uint8_t magic_bytes[4] = {
        static_cast<uint8_t>(magic >> 24),
        static_cast<uint8_t>(magic >> 16),
        static_cast<uint8_t>(magic >> 8),
        static_cast<uint8_t>(magic)
    };
    if (std::fwrite(magic_bytes, 1, 4, f) != 4) {
        std::fclose(f);
        return BlockPos{};
    }

    // Write block size (little-endian uint32)
    uint8_t size_bytes[4] = {
        static_cast<uint8_t>(block_size),
        static_cast<uint8_t>(block_size >> 8),
        static_cast<uint8_t>(block_size >> 16),
        static_cast<uint8_t>(block_size >> 24)
    };
    if (std::fwrite(size_bytes, 1, 4, f) != 4) {
        std::fclose(f);
        return BlockPos{};
    }

    // Write block data
    if (std::fwrite(block_data.data(), 1, block_size, f) != block_size) {
        std::fclose(f);
        return BlockPos{};
    }

    std::fclose(f);

    // Update current offset
    current_offset_ += entry_size;

    return pos;
}

// ---------------------------------------------------------------------------
// read_block
// ---------------------------------------------------------------------------

bool BlockStore::read_block(const BlockPos& pos, CBlock& block) const {
    if (pos.is_null()) return false;

    std::string path = get_block_path(pos.file_num);
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        fprintf(stderr, "BlockStore: failed to open %s for reading: %s\n",
                path.c_str(), std::strerror(errno));
        return false;
    }

    // Seek to the block entry position
    if (std::fseek(f, pos.offset, SEEK_SET) != 0) {
        std::fclose(f);
        return false;
    }

    // Read and verify magic bytes
    uint8_t magic_bytes[4];
    if (std::fread(magic_bytes, 1, 4, f) != 4) {
        std::fclose(f);
        return false;
    }

    uint32_t magic = (static_cast<uint32_t>(magic_bytes[0]) << 24)
                   | (static_cast<uint32_t>(magic_bytes[1]) << 16)
                   | (static_cast<uint32_t>(magic_bytes[2]) << 8)
                   |  static_cast<uint32_t>(magic_bytes[3]);

    if (magic != consensus::MAINNET_MAGIC) {
        fprintf(stderr, "BlockStore: bad magic 0x%08x at file %d offset %u\n",
                magic, pos.file_num, pos.offset);
        std::fclose(f);
        return false;
    }

    // Read block size (little-endian uint32)
    uint8_t size_bytes[4];
    if (std::fread(size_bytes, 1, 4, f) != 4) {
        std::fclose(f);
        return false;
    }

    uint32_t block_size = static_cast<uint32_t>(size_bytes[0])
                        | (static_cast<uint32_t>(size_bytes[1]) << 8)
                        | (static_cast<uint32_t>(size_bytes[2]) << 16)
                        | (static_cast<uint32_t>(size_bytes[3]) << 24);

    // Sanity check: block size should not exceed MAX_BLOCK_SIZE
    if (block_size > consensus::MAX_BLOCK_SIZE) {
        fprintf(stderr, "BlockStore: block size %u exceeds max at file %d offset %u\n",
                block_size, pos.file_num, pos.offset);
        std::fclose(f);
        return false;
    }

    // Read block data
    std::vector<uint8_t> block_data(block_size);
    if (std::fread(block_data.data(), 1, block_size, f) != block_size) {
        std::fclose(f);
        return false;
    }

    std::fclose(f);

    // Deserialize
    return deserialize_block(block_data.data(), block_data.size(), block);
}

// ---------------------------------------------------------------------------
// flush
// ---------------------------------------------------------------------------

void BlockStore::flush() {
    // Open and close the current file with fflush to force OS write-through.
    // In practice, each write already closes the file, so this is mainly
    // for use after batched writes if the write path is changed to keep
    // the file handle open.
    std::string path = get_block_path(current_file_);
    FILE* f = std::fopen(path.c_str(), "ab");
    if (f) {
        std::fflush(f);

        // fsync for durability
#ifdef _WIN32
        _commit(_fileno(f));
#else
        int fd = fileno(f);
        if (fd >= 0) {
            ::fsync(fd);
        }
#endif
        std::fclose(f);
    }
}

} // namespace flow
