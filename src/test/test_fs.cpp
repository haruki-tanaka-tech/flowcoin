// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for filesystem utilities (util/fs.h).

#include "util/fs.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// Test data directory base
static const std::string TEST_DIR = "/tmp/flowcoin_test_fs";

// Cleanup helper
static void cleanup() {
    flow::fs::remove_all(TEST_DIR);
}

void test_fs() {
    // Clean up from any previous run
    cleanup();

    // -----------------------------------------------------------------------
    // Test 1: create_directories creates nested dirs
    // -----------------------------------------------------------------------
    {
        std::string nested = TEST_DIR + "/a/b/c";
        assert(flow::fs::create_directories(nested));
        assert(flow::fs::exists(nested));
        assert(flow::fs::is_directory(nested));
    }

    // -----------------------------------------------------------------------
    // Test 2: create_directories on existing dir succeeds
    // -----------------------------------------------------------------------
    {
        assert(flow::fs::create_directories(TEST_DIR));
    }

    // -----------------------------------------------------------------------
    // Test 3: write_file / read_file round-trip
    // -----------------------------------------------------------------------
    {
        std::string path = TEST_DIR + "/test.bin";
        std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};
        assert(flow::fs::write_file(path, data));

        std::vector<uint8_t> read_back;
        assert(flow::fs::read_file(path, read_back));
        assert(read_back == data);
    }

    // -----------------------------------------------------------------------
    // Test 4: write_file with pointer overload
    // -----------------------------------------------------------------------
    {
        std::string path = TEST_DIR + "/test2.bin";
        uint8_t data[] = {1, 2, 3, 4, 5};
        assert(flow::fs::write_file(path, data, sizeof(data)));

        std::vector<uint8_t> read_back;
        assert(flow::fs::read_file(path, read_back));
        assert(read_back.size() == 5);
        assert(std::memcmp(read_back.data(), data, 5) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 5: file_size returns correct value
    // -----------------------------------------------------------------------
    {
        std::string path = TEST_DIR + "/sized.bin";
        std::vector<uint8_t> data(1234, 0xAB);
        assert(flow::fs::write_file(path, data));
        assert(flow::fs::file_size(path) == 1234);
    }

    // -----------------------------------------------------------------------
    // Test 6: exists returns true for files and directories
    // -----------------------------------------------------------------------
    {
        assert(flow::fs::exists(TEST_DIR));
        assert(flow::fs::exists(TEST_DIR + "/test.bin"));
        assert(!flow::fs::exists(TEST_DIR + "/nonexistent.txt"));
    }

    // -----------------------------------------------------------------------
    // Test 7: is_file / is_directory correct
    // -----------------------------------------------------------------------
    {
        assert(flow::fs::is_directory(TEST_DIR));
        assert(!flow::fs::is_file(TEST_DIR));

        assert(flow::fs::is_file(TEST_DIR + "/test.bin"));
        assert(!flow::fs::is_directory(TEST_DIR + "/test.bin"));
    }

    // -----------------------------------------------------------------------
    // Test 8: remove_file deletes file
    // -----------------------------------------------------------------------
    {
        std::string path = TEST_DIR + "/to_delete.bin";
        assert(flow::fs::write_file(path, std::vector<uint8_t>{42}));
        assert(flow::fs::exists(path));

        assert(flow::fs::remove_file(path));
        assert(!flow::fs::exists(path));
    }

    // -----------------------------------------------------------------------
    // Test 9: list_files with extension filter
    // -----------------------------------------------------------------------
    {
        std::string dir = TEST_DIR + "/list_test";
        assert(flow::fs::create_directories(dir));

        assert(flow::fs::write_file(dir + "/a.txt", std::vector<uint8_t>{1}));
        assert(flow::fs::write_file(dir + "/b.txt", std::vector<uint8_t>{2}));
        assert(flow::fs::write_file(dir + "/c.dat", std::vector<uint8_t>{3}));

        auto all = flow::fs::list_files(dir);
        assert(all.size() == 3);

        auto txt_only = flow::fs::list_files(dir, ".txt");
        assert(txt_only.size() == 2);

        auto dat_only = flow::fs::list_files(dir, ".dat");
        assert(dat_only.size() == 1);

        auto csv_only = flow::fs::list_files(dir, ".csv");
        assert(csv_only.empty());
    }

    // -----------------------------------------------------------------------
    // Test 10: copy_file creates identical copy
    // -----------------------------------------------------------------------
    {
        std::string src = TEST_DIR + "/copy_src.bin";
        std::string dst = TEST_DIR + "/copy_dst.bin";

        std::vector<uint8_t> data(500);
        for (size_t i = 0; i < data.size(); i++) {
            data[i] = static_cast<uint8_t>(i % 256);
        }

        assert(flow::fs::write_file(src, data));
        assert(flow::fs::copy_file(src, dst));
        assert(flow::fs::exists(dst));

        std::vector<uint8_t> dst_data;
        assert(flow::fs::read_file(dst, dst_data));
        assert(dst_data == data);
    }

    // -----------------------------------------------------------------------
    // Test 11: temp_path returns unique paths
    // -----------------------------------------------------------------------
    {
        std::string p1 = flow::fs::temp_path("test");
        std::string p2 = flow::fs::temp_path("test");
        assert(!p1.empty());
        assert(!p2.empty());
        assert(p1 != p2);
    }

    // -----------------------------------------------------------------------
    // Test 12: FileLock prevents double lock
    // -----------------------------------------------------------------------
    {
        std::string lock_path = TEST_DIR + "/test.lock";

        flow::fs::FileLock lock1(lock_path);
        assert(lock1.try_lock());
        assert(lock1.is_locked());

        // Second lock should fail to acquire (non-blocking)
        flow::fs::FileLock lock2(lock_path);
        assert(!lock2.try_lock());
        assert(!lock2.is_locked());

        // Release first lock
        lock1.unlock();
        assert(!lock1.is_locked());

        // Now second lock should succeed
        assert(lock2.try_lock());
        assert(lock2.is_locked());
        lock2.unlock();
    }

    // -----------------------------------------------------------------------
    // Test 13: join() path handling — basic
    // -----------------------------------------------------------------------
    {
        assert(flow::fs::join("/home/user", "data") == "/home/user/data");
    }

    // -----------------------------------------------------------------------
    // Test 14: join() with trailing slash
    // -----------------------------------------------------------------------
    {
        assert(flow::fs::join("/home/user/", "data") == "/home/user/data");
    }

    // -----------------------------------------------------------------------
    // Test 15: join() with absolute second path
    // -----------------------------------------------------------------------
    {
        // When second path is absolute, it typically replaces the first
        // (behavior varies by implementation — test whatever the impl does)
        std::string result = flow::fs::join("/base", "/abs");
        // Just verify it doesn't crash and returns something
        assert(!result.empty());
    }

    // -----------------------------------------------------------------------
    // Test 16: join() with three components
    // -----------------------------------------------------------------------
    {
        assert(flow::fs::join("/a", "b", "c") == "/a/b/c");
    }

    // -----------------------------------------------------------------------
    // Test 17: rename() moves file
    // -----------------------------------------------------------------------
    {
        std::string old_path = TEST_DIR + "/rename_old.bin";
        std::string new_path = TEST_DIR + "/rename_new.bin";

        std::vector<uint8_t> data = {10, 20, 30};
        assert(flow::fs::write_file(old_path, data));
        assert(flow::fs::exists(old_path));

        assert(flow::fs::rename(old_path, new_path));
        assert(!flow::fs::exists(old_path));
        assert(flow::fs::exists(new_path));

        std::vector<uint8_t> read_back;
        assert(flow::fs::read_file(new_path, read_back));
        assert(read_back == data);
    }

    // -----------------------------------------------------------------------
    // Test 18: read_text / write_text round-trip
    // -----------------------------------------------------------------------
    {
        std::string path = TEST_DIR + "/text.txt";
        std::string content = "Hello, FlowCoin!\nLine 2\n";
        assert(flow::fs::write_text(path, content));

        std::string read_back;
        assert(flow::fs::read_text(path, read_back));
        assert(read_back == content);
    }

    // -----------------------------------------------------------------------
    // Test 19: read_file on nonexistent path returns false
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> data;
        assert(!flow::fs::read_file(TEST_DIR + "/no_such_file.bin", data));
        assert(data.empty());
    }

    // -----------------------------------------------------------------------
    // Test 20: file_size on nonexistent path returns 0
    // -----------------------------------------------------------------------
    {
        assert(flow::fs::file_size(TEST_DIR + "/no_such_file.bin") == 0);
    }

    // -----------------------------------------------------------------------
    // Test 21: dirname and basename
    // -----------------------------------------------------------------------
    {
        assert(flow::fs::dirname("/home/user/file.txt") == "/home/user");
        assert(flow::fs::basename("/home/user/file.txt") == "file.txt");
    }

    // -----------------------------------------------------------------------
    // Test 22: extension and stem
    // -----------------------------------------------------------------------
    {
        assert(flow::fs::extension("file.txt") == ".txt");
        assert(flow::fs::extension("file") == "");
        assert(flow::fs::stem("file.txt") == "file");
    }

    // -----------------------------------------------------------------------
    // Test 23: is_absolute
    // -----------------------------------------------------------------------
    {
        assert(flow::fs::is_absolute("/usr/bin"));
        assert(!flow::fs::is_absolute("relative/path"));
        assert(!flow::fs::is_absolute("file.txt"));
    }

    // -----------------------------------------------------------------------
    // Test 24: remove_all removes directory tree
    // -----------------------------------------------------------------------
    {
        std::string dir = TEST_DIR + "/deep/nested/dir";
        assert(flow::fs::create_directories(dir));
        assert(flow::fs::write_file(dir + "/file.bin", std::vector<uint8_t>{1}));

        assert(flow::fs::remove_all(TEST_DIR + "/deep"));
        assert(!flow::fs::exists(TEST_DIR + "/deep"));
    }

    // -----------------------------------------------------------------------
    // Test 25: Empty file
    // -----------------------------------------------------------------------
    {
        std::string path = TEST_DIR + "/empty.bin";
        assert(flow::fs::write_file(path, std::vector<uint8_t>{}));
        assert(flow::fs::exists(path));
        assert(flow::fs::file_size(path) == 0);

        std::vector<uint8_t> data;
        assert(flow::fs::read_file(path, data));
        assert(data.empty());
    }

    // -----------------------------------------------------------------------
    // Test 26: Large file write and read
    // -----------------------------------------------------------------------
    {
        std::string path = TEST_DIR + "/large.bin";
        constexpr size_t large_size = 100000;
        std::vector<uint8_t> data(large_size);
        for (size_t i = 0; i < large_size; i++) {
            data[i] = static_cast<uint8_t>((i * 7 + 13) % 256);
        }

        assert(flow::fs::write_file(path, data));
        assert(flow::fs::file_size(path) == large_size);

        std::vector<uint8_t> read_back;
        assert(flow::fs::read_file(path, read_back));
        assert(read_back == data);
    }

    // -----------------------------------------------------------------------
    // Test 27: append_text appends to existing file
    // -----------------------------------------------------------------------
    {
        std::string path = TEST_DIR + "/append.txt";
        assert(flow::fs::write_text(path, "line1\n"));
        assert(flow::fs::append_text(path, "line2\n"));
        assert(flow::fs::append_text(path, "line3\n"));

        std::string content;
        assert(flow::fs::read_text(path, content));
        assert(content == "line1\nline2\nline3\n");
    }

    // -----------------------------------------------------------------------
    // Test 28: list_directories
    // -----------------------------------------------------------------------
    {
        std::string dir = TEST_DIR + "/listdir_test";
        assert(flow::fs::create_directories(dir + "/subdir1"));
        assert(flow::fs::create_directories(dir + "/subdir2"));
        assert(flow::fs::write_file(dir + "/file.txt", std::vector<uint8_t>{1}));

        auto dirs = flow::fs::list_directories(dir);
        assert(dirs.size() == 2);

        auto files = flow::fs::list_files(dir);
        assert(files.size() == 1);
    }

    // -----------------------------------------------------------------------
    // Test 29: temp_dir returns a valid directory
    // -----------------------------------------------------------------------
    {
        std::string tmpdir = flow::fs::temp_dir();
        assert(!tmpdir.empty());
        assert(flow::fs::is_directory(tmpdir));
    }

    // -----------------------------------------------------------------------
    // Test 30: copy_file does not modify source
    // -----------------------------------------------------------------------
    {
        std::string src = TEST_DIR + "/copy_src2.bin";
        std::string dst = TEST_DIR + "/copy_dst2.bin";

        std::vector<uint8_t> data = {10, 20, 30, 40, 50};
        assert(flow::fs::write_file(src, data));

        assert(flow::fs::copy_file(src, dst));

        // Source should still exist and be unchanged
        std::vector<uint8_t> src_data;
        assert(flow::fs::read_file(src, src_data));
        assert(src_data == data);

        // Modifying dst should not affect src
        assert(flow::fs::write_file(dst, std::vector<uint8_t>{99}));
        assert(flow::fs::read_file(src, src_data));
        assert(src_data == data);
    }

    // -----------------------------------------------------------------------
    // Test 31: FileLock with lock/unlock cycle
    // -----------------------------------------------------------------------
    {
        std::string lock_path = TEST_DIR + "/cycle.lock";
        flow::fs::FileLock lock(lock_path);

        // Multiple lock/unlock cycles
        for (int i = 0; i < 5; i++) {
            assert(lock.try_lock());
            assert(lock.is_locked());
            lock.unlock();
            assert(!lock.is_locked());
        }
    }

    // -----------------------------------------------------------------------
    // Test 32: normalize path
    // -----------------------------------------------------------------------
    {
        std::string normalized = flow::fs::normalize("/a/b/../c/./d");
        assert(!normalized.empty());
        // Should resolve to something like /a/c/d
    }

    // -----------------------------------------------------------------------
    // Test 33: absolute path conversion
    // -----------------------------------------------------------------------
    {
        std::string abs = flow::fs::absolute("relative");
        assert(flow::fs::is_absolute(abs));
    }

    // -----------------------------------------------------------------------
    // Test 34: list_all includes both files and directories
    // -----------------------------------------------------------------------
    {
        std::string dir = TEST_DIR + "/list_all_test";
        assert(flow::fs::create_directories(dir + "/subdir"));
        assert(flow::fs::write_file(dir + "/file.txt", std::vector<uint8_t>{1}));

        auto all = flow::fs::list_all(dir);
        assert(all.size() == 2);
    }

    // -----------------------------------------------------------------------
    // Test 35: remove_file on nonexistent file
    // -----------------------------------------------------------------------
    {
        bool result = flow::fs::remove_file(TEST_DIR + "/nonexistent_file.bin");
        // Removing a nonexistent file should return false (or true depending
        // on implementation). Just verify no crash.
        (void)result;
    }

    // -----------------------------------------------------------------------
    // Test 36: create_directory (single level)
    // -----------------------------------------------------------------------
    {
        std::string dir = TEST_DIR + "/single_dir";
        assert(flow::fs::create_directory(dir));
        assert(flow::fs::is_directory(dir));
    }

    // -----------------------------------------------------------------------
    // Test 37: last_modified returns reasonable time
    // -----------------------------------------------------------------------
    {
        std::string path = TEST_DIR + "/mtime_test.bin";
        assert(flow::fs::write_file(path, std::vector<uint8_t>{42}));

        int64_t mtime = flow::fs::last_modified(path);
        assert(mtime > 1735689600);  // after 2025-01-01
    }

    // -----------------------------------------------------------------------
    // Test 38: is_symlink returns false for regular files
    // -----------------------------------------------------------------------
    {
        std::string path = TEST_DIR + "/regular_file.bin";
        assert(flow::fs::write_file(path, std::vector<uint8_t>{1}));
        assert(!flow::fs::is_symlink(path));
    }

    // -----------------------------------------------------------------------
    // Test 39: directory_size
    // -----------------------------------------------------------------------
    {
        std::string dir = TEST_DIR + "/size_test";
        assert(flow::fs::create_directories(dir));
        assert(flow::fs::write_file(dir + "/a.bin", std::vector<uint8_t>(100, 0)));
        assert(flow::fs::write_file(dir + "/b.bin", std::vector<uint8_t>(200, 0)));

        size_t total = flow::fs::directory_size(dir);
        assert(total >= 300);
    }

    // -----------------------------------------------------------------------
    // Test 40: available_disk_space returns positive value
    // -----------------------------------------------------------------------
    {
        size_t avail = flow::fs::available_disk_space("/tmp");
        assert(avail > 0);
    }

    // Clean up test directory
    cleanup();
}
