// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Flat-file block storage using the Bitcoin Core blk*.dat pattern.
// Each block is stored as: [4-byte magic] [4-byte size] [serialized block data].
// Files are capped at MAX_FILE_SIZE and roll over to the next numbered file.

#ifndef FLOWCOIN_CHAIN_BLOCKSTORE_H
#define FLOWCOIN_CHAIN_BLOCKSTORE_H

#include "chain/blockindex.h"
#include "primitives/block.h"
#include <cstdint>
#include <string>

namespace flow {

class BlockStore {
public:
    /// Initialize with data directory path. Creates blocks/ subdirectory if needed.
    explicit BlockStore(const std::string& datadir);

    /// Write a block to disk. Returns its position on success.
    /// On failure, returns a null BlockPos (file_num < 0).
    BlockPos write_block(const CBlock& block);

    /// Read a block from disk at the given position.
    /// Returns true on success, false on any I/O or deserialization error.
    bool read_block(const BlockPos& pos, CBlock& block) const;

    /// Flush any OS-buffered writes to disk.
    void flush();

    // ---- Undo data (rev*.dat files, mirroring blk*.dat) --------------------

    /// Write undo data to rev<file_num>.dat (appended at end).
    /// file_num should match the blk file that contains the block.
    /// On success, returns true and sets out_offset to the write position.
    bool write_undo(int file_num, const std::vector<uint8_t>& undo_data,
                    uint32_t& out_offset);

    /// Read undo data from rev<file_num>.dat at the given offset.
    /// Returns true on success, populating undo_data.
    bool read_undo(int file_num, uint32_t offset,
                   std::vector<uint8_t>& undo_data) const;

    /// Check if a block index entry has valid undo position.
    static bool has_undo(const CBlockIndex& index) { return index.has_undo(); }

    // ---- File management ---------------------------------------------------

    /// Prune block and undo files for blocks below the given height.
    /// Deletes entire blk/rev files that contain only blocks below the cutoff.
    /// Returns the number of files deleted.
    int prune_files(uint64_t below_height);

    /// Get total disk usage of all blk*.dat and rev*.dat files (bytes).
    size_t get_disk_usage() const;

    /// Scan existing block files on startup.
    /// Returns the number of blk*.dat files found.
    int scan_block_files();

    /// Get the number of block files currently in use.
    int file_count() const { return current_file_ + 1; }

    /// Get the current file number being written to.
    int current_file_num() const { return current_file_; }

    /// Get the current write offset in the current file.
    uint32_t current_write_offset() const { return current_offset_; }

    /// Acquire an advisory file lock to prevent multiple processes
    /// from writing to the same block files.
    bool acquire_lock();

    /// Release the advisory file lock.
    void release_lock();

    /// Check if the lock is currently held.
#ifdef _WIN32
    bool is_locked() const { return lock_handle_ != reinterpret_cast<void*>(static_cast<intptr_t>(-1)); }
#else
    bool is_locked() const { return lock_fd_ >= 0; }
#endif

private:
    std::string datadir_;
    int current_file_ = 0;
    uint32_t current_offset_ = 0;
#ifdef _WIN32
    void* lock_handle_ = reinterpret_cast<void*>(static_cast<intptr_t>(-1)); // INVALID_HANDLE_VALUE
#else
    int lock_fd_ = -1;     // File descriptor for advisory lock
#endif

    /// Maximum file size before rolling to a new blk file (128 MB).
    static constexpr size_t MAX_FILE_SIZE = 128 * 1024 * 1024;

    /// Maximum undo file size before rolling (64 MB).
    static constexpr size_t MAX_UNDO_FILE_SIZE = 64 * 1024 * 1024;

    /// Get the filesystem path for a given blk file number.
    /// Format: <datadir>/blocks/blk00000.dat, blk00001.dat, etc.
    std::string get_block_path(int file_num) const;

    /// Get the filesystem path for a given rev (undo) file number.
    /// Format: <datadir>/blocks/rev00000.dat, rev00001.dat, etc.
    std::string get_undo_path(int file_num) const;

    /// Get the lock file path.
    std::string get_lock_path() const;

    /// Serialize a full block into a byte vector.
    std::vector<uint8_t> serialize_block(const CBlock& block) const;

    /// Deserialize a full block from a byte vector.
    bool deserialize_block(const uint8_t* data, size_t len, CBlock& block) const;

    /// Get the file size of a given path (0 if not found).
    static size_t get_file_size(const std::string& path);

public:
    // ═══ Extended block file operations ═══

    /// Block file metadata.
    struct FileInfo {
        int file_num;
        size_t size;
        size_t max_size;
        uint64_t height_lo;
        uint64_t height_hi;
        int block_count;
    };

    /// Get metadata for all block files.
    std::vector<FileInfo> get_file_info() const;

    /// Read a block at a known position (convenience alias for read_block).
    bool read_block_at(const BlockPos& pos, CBlock& block) const;

    /// Structured undo data with model hash tracking.
    struct UndoData {
        uint64_t height;
        std::vector<uint8_t> spent_outputs_raw;
        uint256 model_hash_before;
    };

    /// Write structured undo data for a block.
    /// file_num should match the block's blk file. out_offset receives the
    /// write position in rev<file_num>.dat for later retrieval.
    bool write_undo_structured(int file_num, const UndoData& undo,
                               uint32_t& out_offset);

    /// Read structured undo data from rev<file_num>.dat at offset.
    bool read_undo_structured(int file_num, uint32_t offset, UndoData& undo) const;

    /// Prune blk/rev files below min_height. Returns bytes freed.
    size_t prune_files_below(uint64_t min_height);

    /// Check if a specific file can be safely pruned.
    bool can_prune(int file_num, uint64_t min_height) const;

    /// Verify integrity of a block file by scanning all entries.
    bool verify_block_file(int file_num) const;

    /// Count total blocks across all files.
    int count_blocks() const;

    /// Defragment a block file (rewrite without gaps).
    bool compact(int file_num);

    /// Read just the header from a block position (faster than full read).
    bool read_block_header(const BlockPos& pos, CBlockHeader& header) const;
};

} // namespace flow

#endif // FLOWCOIN_CHAIN_BLOCKSTORE_H
