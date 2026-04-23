// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// ANSI color codes + timestamped tagged logging for flowcoin-miner.
// Layout mirrors XMRig: `[YYYY-MM-DD HH:MM:SS.mmm]  TAG    message`.

#ifndef FLOWCOIN_MINER_LOG_HPP
#define FLOWCOIN_MINER_LOG_HPP

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <string>

namespace miner {

// ---------------------------------------------------------------------------
// ANSI colors. Mirrors XMRig's palette so the miner feels familiar.
// ---------------------------------------------------------------------------

#define CSI              "\x1B["
#define CLEAR            CSI "0m"

#define BLACK_BOLD_S     CSI "1;30m"
#define RED_S            CSI "0;31m"
#define RED_BOLD_S       CSI "1;31m"
#define GREEN_S          CSI "0;32m"
#define GREEN_BOLD_S     CSI "1;32m"
#define YELLOW_S         CSI "0;33m"
#define YELLOW_BOLD_S    CSI "1;33m"
#define BLUE_S           CSI "0;34m"
#define BLUE_BOLD_S      CSI "1;34m"
#define MAGENTA_S        CSI "0;35m"
#define MAGENTA_BOLD_S   CSI "1;35m"
#define CYAN_S           CSI "0;36m"
#define CYAN_BOLD_S      CSI "1;36m"
#define WHITE_S          CSI "0;37m"
#define WHITE_BOLD_S     CSI "1;37m"

#define BLUE_BG_S        CSI "44m"
#define CYAN_BG_BOLD_S   CSI "46;1m"
#define GREEN_BG_BOLD_S  CSI "42;1m"
#define MAGENTA_BG_BOLD_S CSI "45;1m"
#define YELLOW_BG_BOLD_S CSI "43;1m"
#define RED_BG_BOLD_S    CSI "41;1m"

#define BLACK_BOLD(x)    BLACK_BOLD_S   x CLEAR
#define RED(x)           RED_S          x CLEAR
#define RED_BOLD(x)      RED_BOLD_S     x CLEAR
#define GREEN(x)         GREEN_S        x CLEAR
#define GREEN_BOLD(x)    GREEN_BOLD_S   x CLEAR
#define YELLOW(x)        YELLOW_S       x CLEAR
#define YELLOW_BOLD(x)   YELLOW_BOLD_S  x CLEAR
#define BLUE_BOLD(x)     BLUE_BOLD_S    x CLEAR
#define MAGENTA(x)       MAGENTA_S      x CLEAR
#define MAGENTA_BOLD(x)  MAGENTA_BOLD_S x CLEAR
#define CYAN(x)          CYAN_S         x CLEAR
#define CYAN_BOLD(x)     CYAN_BOLD_S    x CLEAR
#define WHITE_BOLD(x)    WHITE_BOLD_S   x CLEAR

// ---------------------------------------------------------------------------
// Log — threadsafe timestamped output with optional ANSI colour stripping.
// ---------------------------------------------------------------------------

class Log {
public:
    static bool& colors() { static bool v = true; return v; }
    static std::mutex& io_mutex() { static std::mutex m; return m; }

    /// Unformatted banner line (no timestamp, no tag) — used for the start-up
    /// summary so the spacing matches XMRig's ` * LABEL       value` look.
    static void banner(const char* fmt, ...) {
        char buf[2048];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        std::string out = colors() ? buf : strip_ansi(buf);
        std::lock_guard<std::mutex> lock(io_mutex());
        std::fputs(out.c_str(), stdout);
        std::fputc('\n', stdout);
        std::fflush(stdout);
    }

    /// Log with explicit tag (already formatted with background colour).
    static void info(const char* tag, const char* fmt, ...) {
        char body[2048];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(body, sizeof(body), fmt, ap);
        va_end(ap);
        emit(tag, body);
    }

    /// Warning — same format as info() but the body renders in yellow by
    /// default. Tag is still passed explicitly so the caller can pick the
    /// right module colour.
    static void warn(const char* tag, const char* fmt, ...) {
        char body[2048];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(body, sizeof(body), fmt, ap);
        va_end(ap);
        std::string coloured = std::string(YELLOW_BOLD_S) + body + CLEAR;
        emit(tag, coloured.c_str());
    }

    static void error(const char* tag, const char* fmt, ...) {
        char body[2048];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(body, sizeof(body), fmt, ap);
        va_end(ap);
        std::string coloured = std::string(RED_BOLD_S) + body + CLEAR;
        emit(tag, coloured.c_str());
    }

private:
    static void emit(const char* tag, const char* body) {
        using namespace std::chrono;
        auto now = system_clock::now();
        auto ms  = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;
        std::time_t tt = system_clock::to_time_t(now);
        std::tm stime{};
#ifdef _WIN32
        localtime_s(&stime, &tt);
#else
        localtime_r(&tt, &stime);
#endif
        char stamp[64];
        std::snprintf(stamp, sizeof(stamp),
                      "[%04d-%02d-%02d %02d:%02d:%02d" BLACK_BOLD_S ".%03d" CLEAR "] ",
                      stime.tm_year + 1900, stime.tm_mon + 1, stime.tm_mday,
                      stime.tm_hour, stime.tm_min, stime.tm_sec,
                      static_cast<int>(ms));

        std::string line = std::string(stamp) + tag + " " + body;
        if (!colors()) line = strip_ansi(line);

        std::lock_guard<std::mutex> lock(io_mutex());
        std::fputs(line.c_str(), stdout);
        std::fputc('\n', stdout);
        std::fflush(stdout);
    }

    static std::string strip_ansi(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); ) {
            if (s[i] == '\x1B' && i + 1 < s.size() && s[i + 1] == '[') {
                i += 2;
                while (i < s.size() && s[i] != 'm') ++i;
                if (i < s.size()) ++i;
            } else {
                out += s[i++];
            }
        }
        return out;
    }
};

// ---------------------------------------------------------------------------
// Tags — 9-character padded badges with background colors (XMRig convention).
// ---------------------------------------------------------------------------

namespace tag {
    inline const char* config()  { return CYAN_BG_BOLD_S    WHITE_BOLD_S " config  " CLEAR; }
    inline const char* net()     { return BLUE_BG_S         WHITE_BOLD_S " net     " CLEAR " "; }
    inline const char* cpu()     { return CYAN_BG_BOLD_S    WHITE_BOLD_S " cpu     " CLEAR; }
    inline const char* miner()   { return MAGENTA_BG_BOLD_S WHITE_BOLD_S " miner   " CLEAR; }
    inline const char* keccak()  { return BLUE_BG_S         WHITE_BOLD_S " keccak  " CLEAR " "; }
    inline const char* bench()   { return GREEN_BG_BOLD_S   WHITE_BOLD_S " bench   " CLEAR; }
    inline const char* signals() { return YELLOW_BG_BOLD_S  WHITE_BOLD_S " signal  " CLEAR; }
}

} // namespace miner

#endif // FLOWCOIN_MINER_LOG_HPP
