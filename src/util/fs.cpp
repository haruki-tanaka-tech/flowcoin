// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "fs.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

namespace flow {
namespace fs {

// ===========================================================================
// Path manipulation
// ===========================================================================

std::string join(const std::string& base, const std::string& rel) {
    if (base.empty()) return rel;
    if (rel.empty()) return base;
    if (rel[0] == '/') return rel;  // rel is absolute

    if (base.back() == '/') {
        return base + rel;
    }
    return base + "/" + rel;
}

std::string join(const std::string& a, const std::string& b, const std::string& c) {
    return join(join(a, b), c);
}

std::string dirname(const std::string& path) {
    if (path.empty()) return ".";

    // Remove trailing slashes
    size_t end = path.size();
    while (end > 1 && path[end - 1] == '/') --end;

    // Find last separator
    size_t pos = path.rfind('/', end - 1);
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}

std::string basename(const std::string& path) {
    if (path.empty()) return "";

    // Remove trailing slashes
    size_t end = path.size();
    while (end > 1 && path[end - 1] == '/') --end;

    // Find last separator
    size_t pos = path.rfind('/', end - 1);
    if (pos == std::string::npos) return path.substr(0, end);
    return path.substr(pos + 1, end - pos - 1);
}

std::string extension(const std::string& path) {
    std::string base = basename(path);
    size_t pos = base.rfind('.');
    if (pos == std::string::npos || pos == 0) return "";
    return base.substr(pos);
}

std::string stem(const std::string& path) {
    std::string ext = extension(path);
    if (ext.empty()) return path;
    return path.substr(0, path.size() - ext.size());
}

std::string normalize(const std::string& path) {
    if (path.empty()) return ".";

    bool is_abs = (path[0] == '/');
    std::vector<std::string> parts;
    std::string component;

    for (size_t i = 0; i < path.size(); ++i) {
        if (path[i] == '/') {
            if (!component.empty()) {
                if (component == "..") {
                    if (!parts.empty() && parts.back() != "..") {
                        parts.pop_back();
                    } else if (!is_abs) {
                        parts.push_back("..");
                    }
                } else if (component != ".") {
                    parts.push_back(component);
                }
                component.clear();
            }
        } else {
            component += path[i];
        }
    }
    if (!component.empty()) {
        if (component == "..") {
            if (!parts.empty() && parts.back() != "..") {
                parts.pop_back();
            } else if (!is_abs) {
                parts.push_back("..");
            }
        } else if (component != ".") {
            parts.push_back(component);
        }
    }

    std::string result;
    if (is_abs) result = "/";
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) result += "/";
        result += parts[i];
    }
    if (result.empty()) return ".";
    return result;
}

std::string absolute(const std::string& path) {
    if (is_absolute(path)) return normalize(path);

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) return path;
    return normalize(join(std::string(cwd), path));
}

bool is_absolute(const std::string& path) {
    return !path.empty() && path[0] == '/';
}

// ===========================================================================
// File/directory existence and properties
// ===========================================================================

bool exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

bool is_file(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    return S_ISREG(st.st_mode);
}

bool is_directory(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode);
}

bool is_symlink(const std::string& path) {
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) return false;
    return S_ISLNK(st.st_mode);
}

size_t file_size(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return 0;
    return static_cast<size_t>(st.st_size);
}

int64_t last_modified(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return 0;
    return static_cast<int64_t>(st.st_mtime);
}

// ===========================================================================
// File operations
// ===========================================================================

bool create_directories(const std::string& path) {
    if (path.empty()) return false;
    if (is_directory(path)) return true;

    // Walk the path creating each component
    std::string current;
    for (size_t i = 0; i < path.size(); ++i) {
        current += path[i];
        if (path[i] == '/' || i == path.size() - 1) {
            if (!current.empty() && current != "/" && !is_directory(current)) {
                if (mkdir(current.c_str(), 0755) != 0 && errno != EEXIST) {
                    return false;
                }
            }
        }
    }
    return is_directory(path);
}

bool create_directory(const std::string& path) {
    if (path.empty()) return false;
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
}

bool remove_file(const std::string& path) {
    return unlink(path.c_str()) == 0;
}

bool remove_directory(const std::string& path) {
    return rmdir(path.c_str()) == 0;
}

bool remove_all(const std::string& path) {
    if (!exists(path)) return true;

    if (is_file(path) || is_symlink(path)) {
        return remove_file(path);
    }

    if (is_directory(path)) {
        // Remove contents first
        auto entries = list_all(path);
        for (const auto& entry : entries) {
            if (!remove_all(entry)) return false;
        }
        return remove_directory(path);
    }

    return false;
}

bool rename(const std::string& from, const std::string& to) {
    return ::rename(from.c_str(), to.c_str()) == 0;
}

bool copy_file(const std::string& from, const std::string& to) {
    int src_fd = open(from.c_str(), O_RDONLY);
    if (src_fd < 0) return false;

    // Get source file permissions
    struct stat st;
    if (fstat(src_fd, &st) != 0) {
        close(src_fd);
        return false;
    }

    int dst_fd = open(to.c_str(), O_WRONLY | O_CREAT | O_TRUNC, st.st_mode);
    if (dst_fd < 0) {
        close(src_fd);
        return false;
    }

    char buf[65536];
    ssize_t n;
    bool success = true;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(dst_fd, buf + written, n - written);
            if (w < 0) {
                if (errno == EINTR) continue;
                success = false;
                break;
            }
            written += w;
        }
        if (!success) break;
    }
    if (n < 0) success = false;

    close(src_fd);
    close(dst_fd);
    return success;
}

// ===========================================================================
// Read/write operations
// ===========================================================================

bool read_file(const std::string& path, std::vector<uint8_t>& data) {
    data.clear();

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return false;
    }

    size_t size = static_cast<size_t>(st.st_size);
    data.resize(size);

    size_t total = 0;
    while (total < size) {
        ssize_t n = read(fd, data.data() + total, size - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            data.clear();
            return false;
        }
        if (n == 0) break;
        total += static_cast<size_t>(n);
    }

    close(fd);
    data.resize(total);
    return true;
}

bool write_file(const std::string& path, const uint8_t* data, size_t len) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;

    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, data + total, len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return false;
        }
        total += static_cast<size_t>(n);
    }

    // Ensure data is flushed to disk
    fsync(fd);
    close(fd);
    return true;
}

bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
    return write_file(path, data.data(), data.size());
}

bool read_text(const std::string& path, std::string& text) {
    text.clear();
    std::vector<uint8_t> data;
    if (!read_file(path, data)) return false;
    text.assign(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

bool write_text(const std::string& path, const std::string& text) {
    return write_file(path, reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

bool append_text(const std::string& path, const std::string& text) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return false;

    size_t total = 0;
    size_t len = text.size();
    const char* data = text.data();
    while (total < len) {
        ssize_t n = write(fd, data + total, len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return false;
        }
        total += static_cast<size_t>(n);
    }

    close(fd);
    return true;
}

bool write_atomic(const std::string& path, const uint8_t* data, size_t len) {
    std::string tmp = path + ".tmp." + std::to_string(getpid());
    if (!write_file(tmp, data, len)) {
        unlink(tmp.c_str());
        return false;
    }
    if (!rename(tmp, path)) {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

bool write_atomic(const std::string& path, const std::vector<uint8_t>& data) {
    return write_atomic(path, data.data(), data.size());
}

// ===========================================================================
// Directory listing
// ===========================================================================

std::vector<std::string> list_files(const std::string& dir, const std::string& ext) {
    std::vector<std::string> result;

    DIR* d = opendir(dir.c_str());
    if (!d) return result;

    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;

        std::string full = join(dir, name);
        if (!is_file(full)) continue;

        if (!ext.empty()) {
            if (extension(name) != ext) continue;
        }

        result.push_back(full);
    }

    closedir(d);
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<std::string> list_directories(const std::string& dir) {
    std::vector<std::string> result;

    DIR* d = opendir(dir.c_str());
    if (!d) return result;

    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;

        std::string full = join(dir, name);
        if (is_directory(full)) {
            result.push_back(full);
        }
    }

    closedir(d);
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<std::string> list_all(const std::string& dir) {
    std::vector<std::string> result;

    DIR* d = opendir(dir.c_str());
    if (!d) return result;

    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        result.push_back(join(dir, name));
    }

    closedir(d);
    std::sort(result.begin(), result.end());
    return result;
}

// ===========================================================================
// Temporary files
// ===========================================================================

std::string temp_path(const std::string& prefix) {
    std::string dir = temp_dir();
    // Generate a unique name using PID and a counter
    static int counter = 0;
    char buf[256];
    std::snprintf(buf, sizeof(buf), "%s_%d_%d_%ld",
                  prefix.c_str(), getpid(), ++counter,
                  static_cast<long>(time(nullptr)));
    return join(dir, std::string(buf));
}

std::string temp_dir() {
    const char* tmpdir = getenv("TMPDIR");
    if (tmpdir && tmpdir[0]) return std::string(tmpdir);
    return "/tmp";
}

// ===========================================================================
// Disk usage
// ===========================================================================

size_t directory_size(const std::string& path) {
    if (!is_directory(path)) {
        if (is_file(path)) return file_size(path);
        return 0;
    }

    size_t total = 0;

    DIR* d = opendir(path.c_str());
    if (!d) return 0;

    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;

        std::string full = join(path, name);
        if (is_file(full)) {
            total += file_size(full);
        } else if (is_directory(full)) {
            total += directory_size(full);
        }
    }

    closedir(d);
    return total;
}

size_t available_disk_space(const std::string& path) {
    struct statvfs st;
    if (statvfs(path.c_str(), &st) != 0) return 0;
    return static_cast<size_t>(st.f_bavail) * static_cast<size_t>(st.f_frsize);
}

size_t total_disk_space(const std::string& path) {
    struct statvfs st;
    if (statvfs(path.c_str(), &st) != 0) return 0;
    return static_cast<size_t>(st.f_blocks) * static_cast<size_t>(st.f_frsize);
}

// ===========================================================================
// File locking
// ===========================================================================

FileLock::FileLock(const std::string& path) : path_(path) {
    fd_ = open(path_.c_str(), O_RDWR | O_CREAT, 0644);
}

FileLock::~FileLock() {
    if (locked_) {
        unlock();
    }
    if (fd_ >= 0) {
        close(fd_);
    }
}

bool FileLock::try_lock() {
    if (fd_ < 0) return false;
    if (locked_) return true;

    if (flock(fd_, LOCK_EX | LOCK_NB) == 0) {
        locked_ = true;
        return true;
    }
    return false;
}

bool FileLock::lock() {
    if (fd_ < 0) return false;
    if (locked_) return true;

    if (flock(fd_, LOCK_EX) == 0) {
        locked_ = true;
        return true;
    }
    return false;
}

void FileLock::unlock() {
    if (fd_ >= 0 && locked_) {
        flock(fd_, LOCK_UN);
        locked_ = false;
    }
}

} // namespace fs
} // namespace flow
