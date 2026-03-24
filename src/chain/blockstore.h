// Copyright (c) 2026 The FlowCoin Developers
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

private:
    std::string datadir_;
    int current_file_ = 0;
    uint32_t current_offset_ = 0;

    /// Maximum file size before rolling to a new blk file (128 MB).
    static constexpr size_t MAX_FILE_SIZE = 128 * 1024 * 1024;

    /// Get the filesystem path for a given blk file number.
    /// Format: <datadir>/blocks/blk00000.dat, blk00001.dat, etc.
    std::string get_block_path(int file_num) const;

    /// Serialize a full block into a byte vector.
    std::vector<uint8_t> serialize_block(const CBlock& block) const;

    /// Deserialize a full block from a byte vector.
    bool deserialize_block(const uint8_t* data, size_t len, CBlock& block) const;
};

} // namespace flow

#endif // FLOWCOIN_CHAIN_BLOCKSTORE_H
