// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Flat-file block storage: blk00001.dat, blk00002.dat, ...
// Each file up to 128 MB, then rolls to next.

#pragma once

#include "core/types.h"
#include "primitives/block.h"

#include <cstdint>
#include <fstream>
#include <string>

namespace flow {

struct BlockPos {
    uint32_t file_num{0};
    uint64_t offset{0};
    uint32_t size{0};
};

class BlockStore {
public:
    explicit BlockStore(const std::string& data_dir);

    // Write a serialized block to disk. Returns its position.
    BlockPos write_block(const std::vector<uint8_t>& block_data);

    // Read a block from disk at a given position.
    std::vector<uint8_t> read_block(const BlockPos& pos) const;

    // Get the data directory path.
    const std::string& data_dir() const { return data_dir_; }

private:
    static constexpr size_t MAX_FILE_SIZE = 128 * 1024 * 1024; // 128 MB

    std::string data_dir_;
    uint32_t current_file_{0};
    uint64_t current_offset_{0};

    std::string file_path(uint32_t file_num) const;
};

} // namespace flow
