// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Filesystem utilities for FlowCoin.
// Provides portable file operations, path manipulation, directory listing,
// temporary file creation, disk space queries, and file locking.
//
// Uses POSIX APIs directly (no std::filesystem) for compatibility with
// older toolchains and deterministic behavior.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace flow {
namespace fs {

// ---------------------------------------------------------------------------
// Path manipulation
// ---------------------------------------------------------------------------

/// Join two path components with a separator.
/// join("/home/user", "data") -> "/home/user/data"
/// join("/home/user/", "data") -> "/home/user/data"
std::string join(const std::string& base, const std::string& rel);

/// Join three path components.
std::string join(const std::string& a, const std::string& b, const std::string& c);

/// Get the directory part of a path.
/// dirname("/home/user/file.txt") -> "/home/user"
/// dirname("file.txt") -> "."
std::string dirname(const std::string& path);

/// Get the filename part of a path.
/// basename("/home/user/file.txt") -> "file.txt"
std::string basename(const std::string& path);

/// Get the file extension (including the dot).
/// extension("file.txt") -> ".txt"
/// extension("file") -> ""
std::string extension(const std::string& path);

/// Remove the file extension.
/// stem("file.txt") -> "file"
/// stem("/path/to/file.tar.gz") -> "/path/to/file.tar"
std::string stem(const std::string& path);

/// Normalize a path (resolve "." and "..").
std::string normalize(const std::string& path);

/// Get the absolute path of a relative path.
std::string absolute(const std::string& path);

/// Check if a path is absolute.
bool is_absolute(const std::string& path);

// ---------------------------------------------------------------------------
// File/directory existence and properties
// ---------------------------------------------------------------------------

/// Check if a path exists (file or directory).
bool exists(const std::string& path);

/// Check if the path is a regular file.
bool is_file(const std::string& path);

/// Check if the path is a directory.
bool is_directory(const std::string& path);

/// Check if the path is a symbolic link.
bool is_symlink(const std::string& path);

/// Get the size of a file in bytes. Returns 0 on error.
size_t file_size(const std::string& path);

/// Get the last modification time of a file (Unix timestamp).
int64_t last_modified(const std::string& path);

// ---------------------------------------------------------------------------
// File operations
// ---------------------------------------------------------------------------

/// Create directories recursively (like mkdir -p).
/// @return true on success (or if directory already exists).
bool create_directories(const std::string& path);

/// Create a single directory.
bool create_directory(const std::string& path);

/// Remove a file.
/// @return true on success.
bool remove_file(const std::string& path);

/// Remove a directory (must be empty).
/// @return true on success.
bool remove_directory(const std::string& path);

/// Remove a directory and all its contents recursively.
/// @return true on success.
bool remove_all(const std::string& path);

/// Rename/move a file or directory.
/// @return true on success.
bool rename(const std::string& from, const std::string& to);

/// Copy a file.
/// @return true on success.
bool copy_file(const std::string& from, const std::string& to);

// ---------------------------------------------------------------------------
// Read/write operations
// ---------------------------------------------------------------------------

/// Read an entire file into a byte vector.
/// @return true on success. On failure, data is cleared.
bool read_file(const std::string& path, std::vector<uint8_t>& data);

/// Write a byte buffer to a file (creates or overwrites).
/// @return true on success.
bool write_file(const std::string& path, const uint8_t* data, size_t len);

/// Write a byte vector to a file.
bool write_file(const std::string& path, const std::vector<uint8_t>& data);

/// Read an entire text file into a string.
/// @return true on success. On failure, text is cleared.
bool read_text(const std::string& path, std::string& text);

/// Write a string to a text file (creates or overwrites).
/// @return true on success.
bool write_text(const std::string& path, const std::string& text);

/// Append a string to a text file.
/// @return true on success.
bool append_text(const std::string& path, const std::string& text);

/// Write atomically: write to a temp file, then rename.
/// Ensures the file is never partially written.
/// @return true on success.
bool write_atomic(const std::string& path, const uint8_t* data, size_t len);
bool write_atomic(const std::string& path, const std::vector<uint8_t>& data);

// ---------------------------------------------------------------------------
// Directory listing
// ---------------------------------------------------------------------------

/// List all files in a directory (non-recursive).
/// If extension is non-empty, only files with that extension are returned.
/// @return Vector of full paths.
std::vector<std::string> list_files(const std::string& dir,
                                     const std::string& extension = "");

/// List all subdirectories in a directory (non-recursive).
/// @return Vector of full paths.
std::vector<std::string> list_directories(const std::string& dir);

/// List all entries (files and directories) in a directory.
/// @return Vector of full paths.
std::vector<std::string> list_all(const std::string& dir);

// ---------------------------------------------------------------------------
// Temporary files
// ---------------------------------------------------------------------------

/// Create a temporary file path with the given prefix.
/// The file is NOT created; only a unique path is returned.
std::string temp_path(const std::string& prefix = "flow");

/// Get the system temporary directory.
std::string temp_dir();

// ---------------------------------------------------------------------------
// Disk usage
// ---------------------------------------------------------------------------

/// Calculate the total size of all files in a directory (recursive).
size_t directory_size(const std::string& path);

/// Get available disk space on the filesystem containing the given path.
size_t available_disk_space(const std::string& path);

/// Get total disk space on the filesystem containing the given path.
size_t total_disk_space(const std::string& path);

// ---------------------------------------------------------------------------
// File locking (advisory, POSIX flock)
// ---------------------------------------------------------------------------

class FileLock {
public:
    /// Construct a file lock for the given path.
    /// The lock file is created if it doesn't exist.
    explicit FileLock(const std::string& path);

    /// Destructor: releases the lock if held.
    ~FileLock();

    /// Try to acquire the lock (non-blocking).
    /// @return true if the lock was acquired.
    bool try_lock();

    /// Acquire the lock (blocking -- waits until available).
    /// @return true on success.
    bool lock();

    /// Release the lock.
    void unlock();

    /// Check if the lock is currently held by this instance.
    bool is_locked() const { return locked_; }

    /// Get the path of the lock file.
    const std::string& path() const { return path_; }

    // Non-copyable
    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;

private:
    int fd_ = -1;
    std::string path_;
    bool locked_ = false;
};

} // namespace fs
} // namespace flow
