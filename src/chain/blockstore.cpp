// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "chain/blockstore.h"
#include "consensus/params.h"
#include "util/serialize.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include "logging.h"

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
    w.write_u32_le(hdr.reserved_field);
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
    hdr.reserved_field  = r.read_u32_le();
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
    // Ensure the blocks/ and blocks/undo/ subdirectories exist
    std::string blocks_dir = datadir_ + "/blocks";
    ::mkdir(blocks_dir.c_str(), 0755);
    std::string undo_dir = blocks_dir + "/undo";
    ::mkdir(undo_dir.c_str(), 0755);

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
        LogError("chain", "failed to open %s for writing: %s",
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
        LogError("chain", "failed to open %s for reading: %s",
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
        LogError("chain", "bad magic 0x%08x at file %d offset %u",
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
        LogError("chain", "block size %u exceeds max at file %d offset %u",
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

// ---------------------------------------------------------------------------
// get_undo_path
// ---------------------------------------------------------------------------

std::string BlockStore::get_undo_path(int file_num) const {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "rev%05d.dat", file_num);
    return datadir_ + "/blocks/" + buf;
}

// ---------------------------------------------------------------------------
// get_undo_path_for_height
// ---------------------------------------------------------------------------

std::string BlockStore::get_undo_path_for_height(uint64_t height) const {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%lu.dat",
                  static_cast<unsigned long>(height));
    return datadir_ + "/blocks/undo/" + buf;
}

// ---------------------------------------------------------------------------
// get_lock_path
// ---------------------------------------------------------------------------

std::string BlockStore::get_lock_path() const {
    return datadir_ + "/blocks/.lock";
}

// ---------------------------------------------------------------------------
// get_file_size
// ---------------------------------------------------------------------------

size_t BlockStore::get_file_size(const std::string& path) {
    struct stat st;
    if (::stat(path.c_str(), &st) == 0) {
        return static_cast<size_t>(st.st_size);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// write_undo — store undo data for a block height
// ---------------------------------------------------------------------------

bool BlockStore::write_undo(uint64_t height, const std::vector<uint8_t>& undo_data) {
    if (undo_data.empty()) return true;

    std::string path = get_undo_path_for_height(height);
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) {
        LogError("chain", "failed to open %s for writing: %s",
                path.c_str(), std::strerror(errno));
        return false;
    }

    // Write length prefix (4 bytes LE) then data
    uint32_t len = static_cast<uint32_t>(undo_data.size());
    uint8_t len_bytes[4] = {
        static_cast<uint8_t>(len),
        static_cast<uint8_t>(len >> 8),
        static_cast<uint8_t>(len >> 16),
        static_cast<uint8_t>(len >> 24)
    };

    if (std::fwrite(len_bytes, 1, 4, f) != 4) {
        std::fclose(f);
        return false;
    }

    if (std::fwrite(undo_data.data(), 1, undo_data.size(), f) != undo_data.size()) {
        std::fclose(f);
        return false;
    }

    std::fclose(f);
    return true;
}

// ---------------------------------------------------------------------------
// read_undo — retrieve undo data for a block height
// ---------------------------------------------------------------------------

bool BlockStore::read_undo(uint64_t height, std::vector<uint8_t>& undo_data) const {
    std::string path = get_undo_path_for_height(height);
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;

    // Read length prefix
    uint8_t len_bytes[4];
    if (std::fread(len_bytes, 1, 4, f) != 4) {
        std::fclose(f);
        return false;
    }

    uint32_t len = static_cast<uint32_t>(len_bytes[0])
                 | (static_cast<uint32_t>(len_bytes[1]) << 8)
                 | (static_cast<uint32_t>(len_bytes[2]) << 16)
                 | (static_cast<uint32_t>(len_bytes[3]) << 24);

    // Sanity check
    if (len > 100'000'000) {
        std::fclose(f);
        return false;
    }

    undo_data.resize(len);
    if (std::fread(undo_data.data(), 1, len, f) != len) {
        std::fclose(f);
        undo_data.clear();
        return false;
    }

    std::fclose(f);
    return true;
}

// ---------------------------------------------------------------------------
// has_undo
// ---------------------------------------------------------------------------

bool BlockStore::has_undo(uint64_t height) const {
    std::string path = get_undo_path_for_height(height);
    struct stat st;
    return ::stat(path.c_str(), &st) == 0 && st.st_size > 0;
}

// ---------------------------------------------------------------------------
// prune_files — delete old blk/rev/undo files
// ---------------------------------------------------------------------------

int BlockStore::prune_files(uint64_t below_height) {
    int files_deleted = 0;

    // Delete per-height undo files
    std::string undo_dir = datadir_ + "/blocks/undo";
    DIR* dir = ::opendir(undo_dir.c_str());
    if (dir) {
        struct dirent* entry;
        while ((entry = ::readdir(dir)) != nullptr) {
            // Parse height from filename like "123.dat"
            char* endp = nullptr;
            unsigned long file_height = std::strtoul(entry->d_name, &endp, 10);
            if (endp && std::strcmp(endp, ".dat") == 0) {
                if (file_height < below_height) {
                    std::string full_path = undo_dir + "/" + entry->d_name;
                    if (::unlink(full_path.c_str()) == 0) {
                        files_deleted++;
                    }
                }
            }
        }
        ::closedir(dir);
    }

    return files_deleted;
}

// ---------------------------------------------------------------------------
// get_disk_usage — total bytes of all blk*.dat and rev*.dat files
// ---------------------------------------------------------------------------

size_t BlockStore::get_disk_usage() const {
    size_t total = 0;

    // Sum blk*.dat files
    for (int i = 0; i <= current_file_ + 1; ++i) {
        std::string path = get_block_path(i);
        total += get_file_size(path);
    }

    // Sum rev*.dat files
    for (int i = 0; i <= current_file_ + 1; ++i) {
        std::string path = get_undo_path(i);
        total += get_file_size(path);
    }

    // Sum undo/<height>.dat files
    std::string undo_dir = datadir_ + "/blocks/undo";
    DIR* dir = ::opendir(undo_dir.c_str());
    if (dir) {
        struct dirent* entry;
        while ((entry = ::readdir(dir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;
            std::string full_path = undo_dir + "/" + entry->d_name;
            total += get_file_size(full_path);
        }
        ::closedir(dir);
    }

    return total;
}

// ---------------------------------------------------------------------------
// scan_block_files — enumerate existing blk*.dat files
// ---------------------------------------------------------------------------

int BlockStore::scan_block_files() {
    int count = 0;
    while (true) {
        std::string path = get_block_path(count);
        struct stat st;
        if (::stat(path.c_str(), &st) != 0) break;
        count++;
    }
    return count;
}

// ---------------------------------------------------------------------------
// acquire_lock — advisory file lock
// ---------------------------------------------------------------------------

bool BlockStore::acquire_lock() {
    std::string lock_path = get_lock_path();
    lock_fd_ = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0644);
    if (lock_fd_ < 0) {
        LogError("chain", "failed to open lock file %s: %s",
                lock_path.c_str(), std::strerror(errno));
        return false;
    }

    if (::flock(lock_fd_, LOCK_EX | LOCK_NB) != 0) {
        LogError("chain", "failed to acquire lock on %s: %s\n"
                "Another FlowCoin instance may be using this data directory.",
                lock_path.c_str(), std::strerror(errno));
        ::close(lock_fd_);
        lock_fd_ = -1;
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// release_lock
// ---------------------------------------------------------------------------

void BlockStore::release_lock() {
    if (lock_fd_ >= 0) {
        ::flock(lock_fd_, LOCK_UN);
        ::close(lock_fd_);
        lock_fd_ = -1;
    }
}

// ---------------------------------------------------------------------------
// BlockStore::FileInfo is defined in blockstore.h
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// get_file_info — enumerate block files with metadata
// ---------------------------------------------------------------------------

std::vector<BlockStore::FileInfo> BlockStore::get_file_info() const {
    std::vector<FileInfo> infos;

    for (int i = 0; i <= current_file_ + 1; ++i) {
        std::string path = get_block_path(i);
        size_t fsize = get_file_size(path);
        if (fsize == 0 && i > current_file_) break;

        FileInfo info;
        info.file_num = i;
        info.size = fsize;
        info.max_size = MAX_FILE_SIZE;
        info.height_lo = UINT64_MAX;
        info.height_hi = 0;
        info.block_count = 0;

        // Scan the file to count blocks and find height range
        FILE* f = std::fopen(path.c_str(), "rb");
        if (f) {
            size_t pos = 0;
            while (pos + 8 < fsize) {
                // Seek to the entry position
                if (std::fseek(f, static_cast<long>(pos), SEEK_SET) != 0) break;

                // Read magic bytes
                uint8_t magic_bytes[4];
                if (std::fread(magic_bytes, 1, 4, f) != 4) break;

                uint32_t magic = (static_cast<uint32_t>(magic_bytes[0]) << 24)
                               | (static_cast<uint32_t>(magic_bytes[1]) << 16)
                               | (static_cast<uint32_t>(magic_bytes[2]) << 8)
                               |  static_cast<uint32_t>(magic_bytes[3]);

                if (magic != consensus::MAINNET_MAGIC) break;

                // Read block size
                uint8_t size_bytes[4];
                if (std::fread(size_bytes, 1, 4, f) != 4) break;

                uint32_t block_size = static_cast<uint32_t>(size_bytes[0])
                                    | (static_cast<uint32_t>(size_bytes[1]) << 8)
                                    | (static_cast<uint32_t>(size_bytes[2]) << 16)
                                    | (static_cast<uint32_t>(size_bytes[3]) << 24);

                if (block_size > consensus::MAX_BLOCK_SIZE) break;

                // Read enough of the block data to extract the height.
                // Height is at offset 128 in the header (after prev_hash[32] +
                // merkle_root[32] + training_hash[32] + dataset_hash[32] = 128).
                if (block_size >= 136) {
                    uint8_t height_buf[8];
                    // Seek to height field
                    if (std::fseek(f, static_cast<long>(pos + 8 + 128), SEEK_SET) == 0) {
                        if (std::fread(height_buf, 1, 8, f) == 8) {
                            uint64_t block_height = 0;
                            for (int j = 0; j < 8; ++j) {
                                block_height |= static_cast<uint64_t>(height_buf[j]) << (j * 8);
                            }

                            if (block_height < info.height_lo) {
                                info.height_lo = block_height;
                            }
                            if (block_height > info.height_hi) {
                                info.height_hi = block_height;
                            }
                        }
                    }
                }

                info.block_count++;
                pos += 8 + block_size;
            }

            std::fclose(f);
        }

        if (info.height_lo == UINT64_MAX) {
            info.height_lo = 0;
        }

        infos.push_back(info);
    }

    return infos;
}

// ---------------------------------------------------------------------------
// read_block_at — read block at a known position (O(1) disk seek)
// ---------------------------------------------------------------------------

bool BlockStore::read_block_at(const BlockPos& pos, CBlock& block) const {
    return read_block(pos, block);
}

// ---------------------------------------------------------------------------
// UndoData — structured undo data for reorg support
// ---------------------------------------------------------------------------

struct UndoData {
    uint64_t height;
    std::vector<uint8_t> spent_outputs_raw;
    uint256 model_hash_before;
};

// ---------------------------------------------------------------------------
// write_undo_structured — write structured undo data
// ---------------------------------------------------------------------------

bool BlockStore::write_undo_structured(uint64_t height, const UndoData& undo) {
    // Serialize the structured undo data
    std::vector<uint8_t> data;

    // Height (8 bytes LE)
    for (int i = 0; i < 8; ++i) {
        data.push_back(static_cast<uint8_t>(undo.height >> (i * 8)));
    }

    // Model hash before (32 bytes)
    data.insert(data.end(), undo.model_hash_before.begin(),
                undo.model_hash_before.end());

    // Spent outputs raw data length (4 bytes LE)
    uint32_t raw_len = static_cast<uint32_t>(undo.spent_outputs_raw.size());
    data.push_back(static_cast<uint8_t>(raw_len));
    data.push_back(static_cast<uint8_t>(raw_len >> 8));
    data.push_back(static_cast<uint8_t>(raw_len >> 16));
    data.push_back(static_cast<uint8_t>(raw_len >> 24));

    // Spent outputs raw data
    data.insert(data.end(), undo.spent_outputs_raw.begin(),
                undo.spent_outputs_raw.end());

    return write_undo(height, data);
}

// ---------------------------------------------------------------------------
// read_undo_structured — read structured undo data
// ---------------------------------------------------------------------------

bool BlockStore::read_undo_structured(uint64_t height, UndoData& undo) const {
    std::vector<uint8_t> raw;
    if (!read_undo(height, raw)) {
        return false;
    }

    // Minimum size: 8 (height) + 32 (model_hash) + 4 (raw_len) = 44
    if (raw.size() < 44) {
        return false;
    }

    size_t pos = 0;

    // Height (8 bytes LE)
    undo.height = 0;
    for (int i = 0; i < 8; ++i) {
        undo.height |= static_cast<uint64_t>(raw[pos + i]) << (i * 8);
    }
    pos += 8;

    // Model hash before (32 bytes)
    std::memcpy(undo.model_hash_before.data(), raw.data() + pos, 32);
    pos += 32;

    // Spent outputs raw length (4 bytes LE)
    uint32_t raw_len = static_cast<uint32_t>(raw[pos])
                     | (static_cast<uint32_t>(raw[pos + 1]) << 8)
                     | (static_cast<uint32_t>(raw[pos + 2]) << 16)
                     | (static_cast<uint32_t>(raw[pos + 3]) << 24);
    pos += 4;

    if (pos + raw_len > raw.size()) {
        return false;
    }

    undo.spent_outputs_raw.assign(raw.begin() + static_cast<ptrdiff_t>(pos),
                                   raw.begin() + static_cast<ptrdiff_t>(pos + raw_len));

    return true;
}

// ---------------------------------------------------------------------------
// read_undo_for_height — convenience wrapper
// ---------------------------------------------------------------------------

bool BlockStore::read_undo_for_height(uint64_t height, std::vector<uint8_t>& undo_data) const {
    return read_undo(height, undo_data);
}

// ---------------------------------------------------------------------------
// prune_files_below — prune blk/rev/undo files below a given height
// ---------------------------------------------------------------------------

size_t BlockStore::prune_files_below(uint64_t min_height) {
    size_t bytes_freed = 0;

    // Step 1: Delete per-height undo files below min_height
    int undo_deleted = prune_files(min_height);
    if (undo_deleted > 0) {
        LogInfo("chain", "pruned %d undo files below height %lu",
                undo_deleted, static_cast<unsigned long>(min_height));
    }

    // Step 2: Check if any blk files can be pruned entirely.
    // A blk file can be pruned if ALL blocks in it are below min_height.
    // We determine this by scanning the file info.
    auto infos = get_file_info();

    for (const auto& info : infos) {
        // Don't prune the current write file
        if (info.file_num >= current_file_) continue;

        // Only prune if the highest block in this file is below min_height
        if (info.height_hi < min_height && info.block_count > 0) {
            // Delete the blk file
            std::string blk_path = get_block_path(info.file_num);
            size_t blk_size = get_file_size(blk_path);
            if (::unlink(blk_path.c_str()) == 0) {
                bytes_freed += blk_size;
                LogInfo("chain", "pruned %s (heights %lu-%lu, %zu bytes)",
                        blk_path.c_str(),
                        static_cast<unsigned long>(info.height_lo),
                        static_cast<unsigned long>(info.height_hi),
                        blk_size);
            }

            // Delete the corresponding rev file if it exists
            std::string rev_path = get_undo_path(info.file_num);
            size_t rev_size = get_file_size(rev_path);
            if (rev_size > 0) {
                if (::unlink(rev_path.c_str()) == 0) {
                    bytes_freed += rev_size;
                }
            }
        }
    }

    return bytes_freed;
}

// ---------------------------------------------------------------------------
// can_prune — check if a specific file can be safely pruned
// ---------------------------------------------------------------------------

bool BlockStore::can_prune(int file_num, uint64_t min_height) const {
    if (file_num >= current_file_) {
        return false;  // Can't prune the active file
    }

    std::string path = get_block_path(file_num);
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;

    // Scan the file to find the maximum height
    uint64_t max_height_in_file = 0;
    size_t pos = 0;

    while (true) {
        if (std::fseek(f, static_cast<long>(pos), SEEK_SET) != 0) break;

        uint8_t magic_bytes[4];
        if (std::fread(magic_bytes, 1, 4, f) != 4) break;

        uint32_t magic = (static_cast<uint32_t>(magic_bytes[0]) << 24)
                       | (static_cast<uint32_t>(magic_bytes[1]) << 16)
                       | (static_cast<uint32_t>(magic_bytes[2]) << 8)
                       |  static_cast<uint32_t>(magic_bytes[3]);

        if (magic != consensus::MAINNET_MAGIC) break;

        uint8_t size_bytes[4];
        if (std::fread(size_bytes, 1, 4, f) != 4) break;

        uint32_t block_size = static_cast<uint32_t>(size_bytes[0])
                            | (static_cast<uint32_t>(size_bytes[1]) << 8)
                            | (static_cast<uint32_t>(size_bytes[2]) << 16)
                            | (static_cast<uint32_t>(size_bytes[3]) << 24);

        if (block_size > consensus::MAX_BLOCK_SIZE) break;

        // Read height from block data
        if (block_size >= 136) {
            if (std::fseek(f, static_cast<long>(pos + 8 + 128), SEEK_SET) == 0) {
                uint8_t height_buf[8];
                if (std::fread(height_buf, 1, 8, f) == 8) {
                    uint64_t block_height = 0;
                    for (int j = 0; j < 8; ++j) {
                        block_height |= static_cast<uint64_t>(height_buf[j]) << (j * 8);
                    }
                    if (block_height > max_height_in_file) {
                        max_height_in_file = block_height;
                    }
                }
            }
        }

        pos += 8 + block_size;
    }

    std::fclose(f);

    return max_height_in_file < min_height;
}

// ---------------------------------------------------------------------------
// verify_block_file — verify integrity of a blk file
// ---------------------------------------------------------------------------

bool BlockStore::verify_block_file(int file_num) const {
    std::string path = get_block_path(file_num);
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;

    // Get file size
    std::fseek(f, 0, SEEK_END);
    long fsize = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        std::fclose(f);
        return false;
    }

    size_t file_size = static_cast<size_t>(fsize);
    size_t pos = 0;
    int block_count = 0;

    while (pos + 8 <= file_size) {
        // Read magic
        if (std::fseek(f, static_cast<long>(pos), SEEK_SET) != 0) break;

        uint8_t magic_bytes[4];
        if (std::fread(magic_bytes, 1, 4, f) != 4) break;

        uint32_t magic = (static_cast<uint32_t>(magic_bytes[0]) << 24)
                       | (static_cast<uint32_t>(magic_bytes[1]) << 16)
                       | (static_cast<uint32_t>(magic_bytes[2]) << 8)
                       |  static_cast<uint32_t>(magic_bytes[3]);

        if (magic != consensus::MAINNET_MAGIC) {
            LogError("chain", "verify: bad magic 0x%08x at file %d offset %zu",
                    magic, file_num, pos);
            std::fclose(f);
            return false;
        }

        // Read size
        uint8_t size_bytes[4];
        if (std::fread(size_bytes, 1, 4, f) != 4) {
            std::fclose(f);
            return false;
        }

        uint32_t block_size = static_cast<uint32_t>(size_bytes[0])
                            | (static_cast<uint32_t>(size_bytes[1]) << 8)
                            | (static_cast<uint32_t>(size_bytes[2]) << 16)
                            | (static_cast<uint32_t>(size_bytes[3]) << 24);

        if (block_size > consensus::MAX_BLOCK_SIZE) {
            LogError("chain", "verify: block size %u exceeds max at file %d offset %zu",
                    block_size, file_num, pos);
            std::fclose(f);
            return false;
        }

        // Verify we can read the full block
        if (pos + 8 + block_size > file_size) {
            LogError("chain", "verify: truncated block at file %d offset %zu "
                    "(need %u bytes, file has %zu remaining)",
                    file_num, pos, block_size,
                    file_size - pos - 8);
            std::fclose(f);
            return false;
        }

        // Try to deserialize the block to verify its integrity
        std::vector<uint8_t> block_data(block_size);
        if (std::fread(block_data.data(), 1, block_size, f) != block_size) {
            std::fclose(f);
            return false;
        }

        CBlock test_block;
        if (!deserialize_block(block_data.data(), block_data.size(), test_block)) {
            LogError("chain", "verify: deserialization failed at file %d offset %zu",
                    file_num, pos);
            std::fclose(f);
            return false;
        }

        pos += 8 + block_size;
        block_count++;
    }

    std::fclose(f);

    LogInfo("chain", "verify: file %d OK (%d blocks, %zu bytes)",
            file_num, block_count, file_size);

    return true;
}

// ---------------------------------------------------------------------------
// count_blocks — count total number of blocks across all files
// ---------------------------------------------------------------------------

int BlockStore::count_blocks() const {
    int total = 0;

    for (int i = 0; i <= current_file_; ++i) {
        std::string path = get_block_path(i);
        FILE* f = std::fopen(path.c_str(), "rb");
        if (!f) continue;

        std::fseek(f, 0, SEEK_END);
        long fsize = std::ftell(f);
        std::fseek(f, 0, SEEK_SET);

        if (fsize <= 0) {
            std::fclose(f);
            continue;
        }

        size_t pos = 0;
        size_t file_size = static_cast<size_t>(fsize);

        while (pos + 8 <= file_size) {
            if (std::fseek(f, static_cast<long>(pos), SEEK_SET) != 0) break;

            uint8_t header[8];
            if (std::fread(header, 1, 8, f) != 8) break;

            uint32_t magic = (static_cast<uint32_t>(header[0]) << 24)
                           | (static_cast<uint32_t>(header[1]) << 16)
                           | (static_cast<uint32_t>(header[2]) << 8)
                           |  static_cast<uint32_t>(header[3]);

            if (magic != consensus::MAINNET_MAGIC) break;

            uint32_t block_size = static_cast<uint32_t>(header[4])
                                | (static_cast<uint32_t>(header[5]) << 8)
                                | (static_cast<uint32_t>(header[6]) << 16)
                                | (static_cast<uint32_t>(header[7]) << 24);

            if (block_size > consensus::MAX_BLOCK_SIZE) break;

            total++;
            pos += 8 + block_size;
        }

        std::fclose(f);
    }

    return total;
}

// ---------------------------------------------------------------------------
// compact — defragment block files by removing gaps
// ---------------------------------------------------------------------------

bool BlockStore::compact(int file_num) {
    std::string path = get_block_path(file_num);
    std::string tmp_path = path + ".compact.tmp";

    FILE* fin = std::fopen(path.c_str(), "rb");
    if (!fin) return false;

    std::fseek(fin, 0, SEEK_END);
    long fsize = std::ftell(fin);
    std::fseek(fin, 0, SEEK_SET);

    if (fsize <= 0) {
        std::fclose(fin);
        return true;
    }

    FILE* fout = std::fopen(tmp_path.c_str(), "wb");
    if (!fout) {
        std::fclose(fin);
        return false;
    }

    size_t pos = 0;
    size_t file_size = static_cast<size_t>(fsize);
    int blocks_written = 0;

    while (pos + 8 <= file_size) {
        if (std::fseek(fin, static_cast<long>(pos), SEEK_SET) != 0) break;

        uint8_t entry_header[8];
        if (std::fread(entry_header, 1, 8, fin) != 8) break;

        uint32_t magic = (static_cast<uint32_t>(entry_header[0]) << 24)
                       | (static_cast<uint32_t>(entry_header[1]) << 16)
                       | (static_cast<uint32_t>(entry_header[2]) << 8)
                       |  static_cast<uint32_t>(entry_header[3]);

        if (magic != consensus::MAINNET_MAGIC) break;

        uint32_t block_size = static_cast<uint32_t>(entry_header[4])
                            | (static_cast<uint32_t>(entry_header[5]) << 8)
                            | (static_cast<uint32_t>(entry_header[6]) << 16)
                            | (static_cast<uint32_t>(entry_header[7]) << 24);

        if (block_size > consensus::MAX_BLOCK_SIZE) break;

        // Read the block data
        std::vector<uint8_t> block_data(block_size);
        if (std::fread(block_data.data(), 1, block_size, fin) != block_size) break;

        // Write to output
        if (std::fwrite(entry_header, 1, 8, fout) != 8) break;
        if (std::fwrite(block_data.data(), 1, block_size, fout) != block_size) break;

        blocks_written++;
        pos += 8 + block_size;
    }

    std::fclose(fin);
    std::fclose(fout);

    // Replace original with compacted file
    if (blocks_written > 0) {
        ::unlink(path.c_str());
        ::rename(tmp_path.c_str(), path.c_str());
    } else {
        ::unlink(tmp_path.c_str());
    }

    return true;
}

// ---------------------------------------------------------------------------
// read_block_header — read just the header from a block position
// ---------------------------------------------------------------------------

bool BlockStore::read_block_header(const BlockPos& pos, CBlockHeader& header) const {
    if (pos.is_null()) return false;

    std::string path = get_block_path(pos.file_num);
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;

    // Seek past the entry header (magic + size = 8 bytes)
    if (std::fseek(f, static_cast<long>(pos.offset + 8), SEEK_SET) != 0) {
        std::fclose(f);
        return false;
    }

    // Read enough data for the header (308 bytes)
    static constexpr size_t HEADER_SIZE = 308;
    if (pos.size < HEADER_SIZE) {
        std::fclose(f);
        return false;
    }

    uint8_t header_data[HEADER_SIZE];
    if (std::fread(header_data, 1, HEADER_SIZE, f) != HEADER_SIZE) {
        std::fclose(f);
        return false;
    }

    std::fclose(f);

    // Deserialize just the header
    DataReader r(header_data, HEADER_SIZE);
    return deserialize_header(r, header);
}

} // namespace flow

