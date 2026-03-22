// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "blockstore.h"
#include "core/serialize.h"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace flow {

BlockStore::BlockStore(const std::string& data_dir) : data_dir_(data_dir) {
    std::filesystem::create_directories(data_dir);

    // Find the latest block file and its size
    for (uint32_t i = 0; ; ++i) {
        auto path = file_path(i);
        if (!std::filesystem::exists(path)) {
            current_file_ = (i > 0) ? i - 1 : 0;
            break;
        }
        current_file_ = i;
    }

    auto path = file_path(current_file_);
    if (std::filesystem::exists(path)) {
        current_offset_ = std::filesystem::file_size(path);
    }
}

std::string BlockStore::file_path(uint32_t file_num) const {
    std::ostringstream ss;
    ss << data_dir_ << "/blk" << std::setw(5) << std::setfill('0') << file_num << ".dat";
    return ss.str();
}

BlockPos BlockStore::write_block(const std::vector<uint8_t>& block_data) {
    // Roll to next file if current is too large
    if (current_offset_ + block_data.size() + 8 > MAX_FILE_SIZE) {
        current_file_++;
        current_offset_ = 0;
    }

    BlockPos pos;
    pos.file_num = current_file_;
    pos.offset = current_offset_;
    pos.size = static_cast<uint32_t>(block_data.size());

    auto path = file_path(current_file_);
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out) {
        throw std::runtime_error("BlockStore: cannot open " + path);
    }

    // Write: [4-byte size LE] [block data]
    uint8_t size_buf[4];
    write_le32(size_buf, pos.size);
    out.write(reinterpret_cast<const char*>(size_buf), 4);
    out.write(reinterpret_cast<const char*>(block_data.data()), block_data.size());
    out.flush();

    if (!out.good()) {
        throw std::runtime_error("BlockStore: write failed (disk full?) " + path);
    }

    current_offset_ += 4 + block_data.size();
    return pos;
}

std::vector<uint8_t> BlockStore::read_block(const BlockPos& pos) const {
    auto path = file_path(pos.file_num);
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("BlockStore: cannot open " + path);
    }

    in.seekg(static_cast<std::streamoff>(pos.offset));

    // Read size prefix
    uint8_t size_buf[4];
    in.read(reinterpret_cast<char*>(size_buf), 4);
    uint32_t size = read_le32(size_buf);

    if (size != pos.size) {
        throw std::runtime_error("BlockStore: size mismatch");
    }

    std::vector<uint8_t> data(size);
    in.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

} // namespace flow
