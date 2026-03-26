/*
 * flowminer.c - FlowCoin solo miner with ncurses TUI.
 * Keccak-256d Proof-of-Work, cgminer-style display.
 */

#include <ncurses.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>

#include "mining.h"
#include "rpc.h"
#include "keccak2.h"
#include "../crypto/ed25519.h"

#include <sys/random.h>

#ifdef USE_OPENCL
#include "ocl_miner.h"
#endif

/* ═══════════════════════════════════════════════════════════════════════
 * Global state
 * ═══════════════════════════════════════════════════════════════════════ */

static volatile int g_running = 1;
static volatile int g_resize  = 0;
static mining_stats_t g_stats;
static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef USE_OPENCL
static volatile int g_using_gpu = 0;
static char g_gpu_name[256] = "";
#endif

/* TUI windows */
static WINDOW *status_win;
static WINDOW *info_win;
static WINDOW *log_win;


/* Log ring buffer for thread-safe logging */
#define LOG_RING_SIZE 256
#define LOG_LINE_MAX  256

static char   g_log_ring[LOG_RING_SIZE][LOG_LINE_MAX];
static int    g_log_head = 0;
static int    g_log_tail = 0;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ═══════════════════════════════════════════════════════════════════════
 * Ed25519 miner keypair
 * ═══════════════════════════════════════════════════════════════════════ */

static uint8_t g_miner_privkey[32];
static uint8_t g_miner_pubkey[32];
static int     g_keypair_loaded = 0;

/*
 * Load or generate the Ed25519 keypair for block signing.
 * Stored in ~/.flowcoin/miner_key.dat (32-byte secret key).
 * The public key is derived from the secret key.
 */
static int load_miner_keypair(void)
{
    char path[512];
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home) return 0;

    snprintf(path, sizeof(path), "%s/.flowcoin/miner_key.dat", home);

    FILE *f = fopen(path, "rb");
    if (f) {
        /* Load existing key */
        size_t n = fread(g_miner_privkey, 1, 32, f);
        fclose(f);
        if (n != 32) {
            fprintf(stderr, "Warning: miner_key.dat is corrupt, regenerating\n");
        } else {
            ed25519_publickey(g_miner_privkey, g_miner_pubkey);
            g_keypair_loaded = 1;
            return 1;
        }
    }

    /* Generate a new keypair */
    if (getrandom(g_miner_privkey, 32, 0) != 32) {
        fprintf(stderr, "Failed to get random bytes for keypair\n");
        return 0;
    }
    ed25519_publickey(g_miner_privkey, g_miner_pubkey);

    /* Ensure directory exists */
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.flowcoin", home);
    mkdir(dir, 0700);

    /* Save the secret key */
    f = fopen(path, "wb");
    if (f) {
        fwrite(g_miner_privkey, 1, 32, f);
        fclose(f);
        chmod(path, 0600);
    } else {
        fprintf(stderr, "Warning: could not save miner_key.dat\n");
    }

    g_keypair_loaded = 1;
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════
 * TUI
 * ═══════════════════════════════════════════════════════════════════════
 *
 * ┌─────────────────────────────────────────────────────┐
 * │ FlowCoin Miner v1.0 - Keccak-256d PoW              │
 * │ (5s):123.4 KH/s (avg):121.0 KH/s                   │
 * │ A:15 R:0 HW:0 WU:0.5/m                             │
 * │ Connected to 127.0.0.1:9334 | Height: 42            │
 * │ Block: 00000000abcd... Diff:1 Best: 12345            │
 * │ [Q]uit                                              │
 * ├─────────────────────────────────────────────────────┤
 * │ 0: CPU   : | 123.4 KH/s | A:15 R:0                 │
 * ├─────────────────────────────────────────────────────┤
 * │ [12:34:56] Found block 43! nonce=1234567             │
 * │ [12:34:50] Mining block 42, target: 00000fff...      │
 * │ [12:34:45] Connected to node, height 41              │
 * └─────────────────────────────────────────────────────┘
 */

static void create_tui_windows(void)
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    if (cols < 40) cols = 40;
    if (rows < 16) rows = 16;

    /* Status area: top 8 lines (including border) */
    status_win = newwin(8, cols, 0, 0);
    /* Device info: 3 lines */
    info_win = newwin(3, cols, 8, 0);
    /* Log area: remaining space */
    int log_rows = rows - 11;
    if (log_rows < 3) log_rows = 3;
    log_win = newwin(log_rows, cols, 11, 0);
    scrollok(log_win, TRUE);
}

static void resize_tui(void)
{
    if (status_win) { delwin(status_win); status_win = NULL; }
    if (info_win)   { delwin(info_win);   info_win   = NULL; }
    if (log_win)    { delwin(log_win);    log_win    = NULL; }
    endwin();
    refresh();
    clear();
    create_tui_windows();
}

static void init_tui(void)
{
    initscr();
    cbreak();
    noecho();
    halfdelay(5);  /* getch() blocks up to 500ms, replaces nodelay+usleep */
    keypad(stdscr, TRUE);

    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_GREEN, COLOR_BLACK);   /* found block  */
        init_pair(2, COLOR_YELLOW, COLOR_BLACK);  /* warnings     */
        init_pair(3, COLOR_RED, COLOR_BLACK);      /* errors       */
        init_pair(4, COLOR_CYAN, COLOR_BLACK);     /* info         */
    }

    curs_set(0);
    create_tui_windows();
}

static void cleanup_tui(void)
{
    if (status_win) delwin(status_win);
    if (info_win)   delwin(info_win);
    if (log_win)    delwin(log_win);
    endwin();
}

static void drain_log_ring(void)
{
    pthread_mutex_lock(&g_log_mutex);
    while (g_log_tail != g_log_head) {
        wprintw(log_win, " %s\n", g_log_ring[g_log_tail]);
        g_log_tail = (g_log_tail + 1) % LOG_RING_SIZE;
    }
    pthread_mutex_unlock(&g_log_mutex);
}

static void update_tui(void)
{
    if (!status_win || !info_win || !log_win) return;

    pthread_mutex_lock(&g_stats_mutex);
    mining_stats_t stats = g_stats;
    pthread_mutex_unlock(&g_stats_mutex);

    int cols = getmaxx(stdscr);
    if (cols < 40) return;  /* terminal too narrow */

    /* ─── Status window ─── */
    werase(status_win);
    box(status_win, 0, 0);

    /* Title */
    wattron(status_win, A_BOLD);
    mvwprintw(status_win, 0, 2, " FlowCoin Miner v1.0 - Keccak-256d PoW ");
    wattroff(status_win, A_BOLD);

    /* Hashrate */
    char hr_5s[64], hr_avg[64];
    format_hashrate(stats.hashrate_5s, hr_5s, sizeof(hr_5s));
    format_hashrate(stats.hashrate_avg, hr_avg, sizeof(hr_avg));
    mvwprintw(status_win, 1, 1, " (5s):%s (avg):%s", hr_5s, hr_avg);

    /* Accepted / Rejected */
    double wu = 0.0;
    if (stats.elapsed_secs > 0)
        wu = stats.blocks_found * 60.0 / stats.elapsed_secs;
    mvwprintw(status_win, 2, 1, " A:%lu R:%lu HW:0 WU:%.1f/m",
              (unsigned long)stats.blocks_found,
              (unsigned long)stats.blocks_rejected, wu);

    /* Connection info */
    mvwprintw(status_win, 3, 1, " Connected to %s:%d | Height: %lu",
              stats.rpc_host, stats.rpc_port,
              (unsigned long)stats.current_height);

    /* Block / Diff / Best share */
    mvwprintw(status_win, 4, 1, " Block: %.16s... Diff:%u Best: %lu",
              stats.best_hash[0] ? stats.best_hash : "(none)",
              stats.difficulty,
              (unsigned long)stats.best_share);

    /* Uptime */
    int up_h = (int)(stats.elapsed_secs / 3600);
    int up_m = (int)((int)stats.elapsed_secs % 3600) / 60;
    int up_s = (int)stats.elapsed_secs % 60;
    mvwprintw(status_win, 5, 1, " Uptime: %02d:%02d:%02d | Hashes: %lu",
              up_h, up_m, up_s, (unsigned long)stats.total_hashes);

    /* Menu */
    wattron(status_win, A_BOLD);
    mvwprintw(status_win, 6, 1, " [Q]uit");
    wattroff(status_win, A_BOLD);

    wnoutrefresh(status_win);

    /* ─── Device info window ─── */
    werase(info_win);
    mvwhline(info_win, 0, 0, ACS_HLINE, cols);
    char dev_hr[64];
    format_hashrate(stats.hashrate_5s, dev_hr, sizeof(dev_hr));
#ifdef USE_OPENCL
    if (g_using_gpu)
        mvwprintw(info_win, 1, 1, " 0: GPU   : %s | %s | A:%lu R:%lu",
                  g_gpu_name, dev_hr,
                  (unsigned long)stats.blocks_found,
                  (unsigned long)stats.blocks_rejected);
    else
#endif
    mvwprintw(info_win, 1, 1, " 0: CPU   : | %s | A:%lu R:%lu",
              dev_hr,
              (unsigned long)stats.blocks_found,
              (unsigned long)stats.blocks_rejected);
    mvwhline(info_win, 2, 0, ACS_HLINE, cols);
    wnoutrefresh(info_win);

    /* ─── Drain log ring ─── */
    drain_log_ring();
    wnoutrefresh(log_win);

    /* Single atomic screen update */
    doupdate();
}

/*
 * Thread-safe log function.  Pushes into the ring buffer;
 * the TUI update loop drains it.
 */
static void tui_log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    char line[LOG_LINE_MAX];
    int off = snprintf(line, sizeof(line), "[%02d:%02d:%02d] ",
                       tm->tm_hour, tm->tm_min, tm->tm_sec);
    vsnprintf(line + off, sizeof(line) - (size_t)off, fmt, args);

    pthread_mutex_lock(&g_log_mutex);
    memcpy(g_log_ring[g_log_head], line, LOG_LINE_MAX);
    g_log_ring[g_log_head][LOG_LINE_MAX - 1] = '\0';
    g_log_head = (g_log_head + 1) % LOG_RING_SIZE;
    if (g_log_head == g_log_tail)
        g_log_tail = (g_log_tail + 1) % LOG_RING_SIZE; /* overwrite oldest */
    pthread_mutex_unlock(&g_log_mutex);

    va_end(args);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Config file reader
 * ═══════════════════════════════════════════════════════════════════════ */

static void read_config_file(miner_config_t *cfg)
{
    char path[512];
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home) return;

    snprintf(path, sizeof(path), "%s/.flowcoin/flowcoin.conf", home);

    FILE *f = fopen(path, "r");
    if (!f) return;

    static char conf_user[128];
    static char conf_pass[128];
    char line[512];

    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0') continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;

        /* Trim leading whitespace */
        while (*key == ' ' || *key == '\t') key++;
        while (*val == ' ' || *val == '\t') val++;

        if (strcmp(key, "rpcuser") == 0) {
            strncpy(conf_user, val, sizeof(conf_user) - 1);
            cfg->rpc_user = conf_user;
        } else if (strcmp(key, "rpcpassword") == 0) {
            strncpy(conf_pass, val, sizeof(conf_pass) - 1);
            cfg->rpc_pass = conf_pass;
        } else if (strcmp(key, "rpcport") == 0) {
            cfg->rpc_port = atoi(val);
        }
    }

    fclose(f);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Mining thread
 * ═══════════════════════════════════════════════════════════════════════ */

static void *mining_thread(void *arg)
{
    miner_config_t *cfg = (miner_config_t *)arg;
    rpc_client_t rpc;

    rpc_init(&rpc, cfg->rpc_host, cfg->rpc_port, cfg->rpc_user, cfg->rpc_pass);

    /* Test connection */
    int64_t height = rpc_getblockcount(&rpc);
    if (height < 0) {
        tui_log("ERROR: Cannot connect to node at %s:%d", cfg->rpc_host, cfg->rpc_port);
        tui_log("Make sure flowcoind is running with -server flag");
        return NULL;
    }
    tui_log("Connected to node, height %ld", (long)height);

    /* Load or generate miner keypair */
    if (!g_keypair_loaded) {
        if (!load_miner_keypair()) {
            tui_log("ERROR: Failed to load/generate miner keypair");
            return NULL;
        }
    }
    {
        char pk_hex[65];
        for (int i = 0; i < 32; i++)
            sprintf(pk_hex + i * 2, "%02x", g_miner_pubkey[i]);
        pk_hex[64] = '\0';
        tui_log("Miner pubkey: %.16s...", pk_hex);
    }

#ifdef USE_OPENCL
    int use_gpu = ocl_init();
    if (use_gpu) {
        snprintf(g_gpu_name, sizeof(g_gpu_name), "%s", ocl_device_name());
        g_using_gpu = 1;
        tui_log("GPU: %s (%.1f GB)", ocl_device_name(),
                ocl_total_memory() / 1e9);
    } else {
        tui_log("No OpenCL GPU found, falling back to CPU");
    }
#else
    tui_log("CPU mining (build with USE_OPENCL=1 for GPU)");
#endif

    uint8_t header[92];
    uint8_t target[32];
    uint32_t nbits;
    uint64_t block_height;
    uint64_t last_logged_height = 0;
    time_t last_template_time = 0;

    while (g_running) {
        /* Get block template */
        if (!rpc_getblocktemplate(&rpc, header, target, &nbits, &block_height)) {
            tui_log("Failed to get block template, retrying in 5s...");
            for (int i = 0; i < 50 && g_running; i++)
                usleep(100000); /* 5s in 100ms chunks */
            continue;
        }
        last_template_time = time(NULL);

        /* Only log when height actually changes */
        if (block_height != last_logged_height) {
            tui_log("Mining block %lu, nbits: %08x, target: %02x%02x%02x%02x%02x%02x",
                    (unsigned long)block_height, nbits,
                    target[0], target[1], target[2], target[3], target[4], target[5]);
            last_logged_height = block_height;
        }

        pthread_mutex_lock(&g_stats_mutex);
        g_stats.current_height = block_height;
        g_stats.difficulty = nbits;
        pthread_mutex_unlock(&g_stats_mutex);

        /* Mine: iterate nonces */
        uint32_t nonce = 0;
        uint64_t hashes_this_block = 0;
        time_t block_start = time(NULL);
        int found = 0;
        int new_block = 0;

        while (g_running && !found && !new_block) {
#ifdef USE_OPENCL
            if (use_gpu) {
                /* GPU path */
                uint32_t batch_count = 1 << 22;  /* 4M per batch */
                uint32_t winning_nonce;

                if (ocl_mine_batch(header, 92, target, 84,
                                   nonce, batch_count, &winning_nonce)) {
                    /* Recompute hash on CPU to verify GPU result */
                    memcpy(header + 84, &winning_nonce, 4);
                    uint8_t hash[32];
                    keccak256d(header, 92, hash);

                    /* CPU-verify: skip false positives from GPU */
                    int cpu_valid = 1;
                    for (int j = 0; j < 32; j++) {
                        if (hash[j] < target[j]) break;
                        if (hash[j] > target[j]) { cpu_valid = 0; break; }
                    }
                    if (!cpu_valid) {
                        /* GPU false positive -- clear nonce and continue */
                        memset(header + 84, 0, 4);
                        nonce += batch_count;
                        if (nonce < batch_count) {
                            /* Nonce overflow: update timestamp silently */
                            int64_t ts = (int64_t)time(NULL);
                            memcpy(header + 72, &ts, 8);
                            nonce = 0;
                            hashes_this_block = 0;
                            block_start = time(NULL);
                        }
                        continue;
                    }

                    found = 1;

                    /* Get new address for this block's reward */
                    char address[128] = {0};
                    rpc_getnewaddress(&rpc, address, sizeof(address));

                    tui_log("*** BLOCK %lu FOUND! nonce=%u ***",
                            (unsigned long)block_height, winning_nonce);

                    char hash_hex[65];
                    for (int k = 0; k < 32; k++)
                        sprintf(hash_hex + k * 2, "%02x", hash[k]);
                    hash_hex[64] = '\0';
                    tui_log("Hash: %.16s...", hash_hex);

                    if (address[0])
                        tui_log("Reward address: %s", address);

                    /* Submit full block with Ed25519 signature */
                    if (rpc_submitblock_full(&rpc, header,
                                            g_miner_privkey, g_miner_pubkey)) {
                        tui_log("Block ACCEPTED by node!");
                        pthread_mutex_lock(&g_stats_mutex);
                        g_stats.blocks_found++;
                        snprintf(g_stats.best_hash, sizeof(g_stats.best_hash),
                                 "%.64s", hash_hex);
                        pthread_mutex_unlock(&g_stats_mutex);
                    } else {
                        tui_log("Block REJECTED by node");
                        pthread_mutex_lock(&g_stats_mutex);
                        g_stats.blocks_rejected++;
                        pthread_mutex_unlock(&g_stats_mutex);
                    }
                }

                hashes_this_block += batch_count;
                nonce += batch_count;

                /* Update hashrate stats */
                time_t now = time(NULL);
                double elapsed = difftime(now, block_start);
                if (elapsed > 0) {
                    double hashrate = (double)hashes_this_block / elapsed;
                    pthread_mutex_lock(&g_stats_mutex);
                    g_stats.hashrate_5s = hashrate;
                    g_stats.total_hashes += batch_count;
                    g_stats.elapsed_secs = difftime(now, g_stats.start_time);
                    if (g_stats.elapsed_secs > 0)
                        g_stats.hashrate_avg = (double)g_stats.total_hashes / g_stats.elapsed_secs;
                    pthread_mutex_unlock(&g_stats_mutex);
                }

                /* Check for new block every 64M hashes */
                if (hashes_this_block % (1ULL << 26) < batch_count) {
                    int64_t cur = rpc_getblockcount(&rpc);
                    if (cur > (int64_t)block_height) {
                        tui_log("New block detected at height %ld, switching...",
                                (long)cur);
                        new_block = 1;
                    }
                }

                /* Re-fetch template every 30s for fresh merkle_root */
                if (difftime(time(NULL), last_template_time) >= 30.0) {
                    new_block = 1;  /* will re-fetch at top of outer loop */
                }

                /* Nonce overflow: silently update timestamp and continue */
                if (nonce < batch_count) {
                    int64_t ts = (int64_t)time(NULL);
                    memcpy(header + 72, &ts, 8);
                    nonce = 0;
                    hashes_this_block = 0;
                    block_start = time(NULL);
                }
            } else
#endif
            {
                /* CPU path: iterate nonces one by one */
                uint32_t batch_start = nonce;
                uint32_t batch_count = 1000000;

                for (uint32_t i = 0; i < batch_count && !found; i++) {
                    /* Set nonce in header at offset 84 */
                    uint32_t n = batch_start + i;
                    memcpy(header + 84, &n, 4);

                    /* Keccak-256d */
                    uint8_t hash[32];
                    keccak256d(header, 92, hash);

                    hashes_this_block++;

                    /* Compare hash against target (big-endian: byte 0 most significant) */
                    int meets = 1;
                    for (int j = 0; j < 32; j++) {
                        if (hash[j] < target[j]) break;      /* hash < target */
                        if (hash[j] > target[j]) { meets = 0; break; } /* hash > target */
                    }

                    if (meets) {
                        found = 1;
                        nonce = n;

                        /* Get new address for this block's reward */
                        char address[128] = {0};
                        rpc_getnewaddress(&rpc, address, sizeof(address));

                        tui_log("*** BLOCK %lu FOUND! nonce=%u ***",
                                (unsigned long)block_height, nonce);

                        char hash_hex[65];
                        for (int k = 0; k < 32; k++)
                            sprintf(hash_hex + k * 2, "%02x", hash[k]);
                        hash_hex[64] = '\0';
                        tui_log("Hash: %.16s...", hash_hex);

                        if (address[0])
                            tui_log("Reward address: %s", address);

                        /* Submit full block with Ed25519 signature */
                        if (rpc_submitblock_full(&rpc, header,
                                                g_miner_privkey, g_miner_pubkey)) {
                            tui_log("Block ACCEPTED by node!");
                            pthread_mutex_lock(&g_stats_mutex);
                            g_stats.blocks_found++;
                            snprintf(g_stats.best_hash, sizeof(g_stats.best_hash),
                                     "%.64s", hash_hex);
                            pthread_mutex_unlock(&g_stats_mutex);
                        } else {
                            tui_log("Block REJECTED by node");
                            pthread_mutex_lock(&g_stats_mutex);
                            g_stats.blocks_rejected++;
                            pthread_mutex_unlock(&g_stats_mutex);
                        }
                    }
                }

                nonce += batch_count;

                /* Update hashrate stats */
                time_t now = time(NULL);
                double elapsed = difftime(now, block_start);
                if (elapsed > 0) {
                    double hashrate = (double)hashes_this_block / elapsed;
                    pthread_mutex_lock(&g_stats_mutex);
                    g_stats.hashrate_5s = hashrate;
                    g_stats.total_hashes += batch_count;
                    g_stats.elapsed_secs = difftime(now, g_stats.start_time);
                    if (g_stats.elapsed_secs > 0) {
                        g_stats.hashrate_avg = (double)g_stats.total_hashes / g_stats.elapsed_secs;
                    }
                    pthread_mutex_unlock(&g_stats_mutex);
                }

                /* Check for new block from network every ~10M hashes */
                if (hashes_this_block % 10000000 < batch_count) {
                    int64_t cur = rpc_getblockcount(&rpc);
                    if (cur > (int64_t)block_height) {
                        tui_log("New block detected at height %ld, switching...",
                                (long)cur);
                        new_block = 1;
                    }
                }

                /* Re-fetch template every 30s for fresh merkle_root */
                if (difftime(time(NULL), last_template_time) >= 30.0) {
                    new_block = 1;  /* will re-fetch at top of outer loop */
                }

                /* Nonce overflow: silently update timestamp and continue */
                if (nonce < batch_count) {
                    int64_t ts = (int64_t)time(NULL);
                    memcpy(header + 72, &ts, 8);
                    nonce = 0;
                    hashes_this_block = 0;
                    block_start = time(NULL);
                }
            }
        }
    }

#ifdef USE_OPENCL
    if (use_gpu) ocl_shutdown();
#endif

    rpc_cleanup(&rpc);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Signal handler
 * ═══════════════════════════════════════════════════════════════════════ */

static void sig_handler(int sig)
{
    if (sig == SIGWINCH) {
        g_resize = 1;
        return;
    }
    g_running = 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    miner_config_t config;
    memset(&config, 0, sizeof(config));
    config.rpc_host = "127.0.0.1";
    config.rpc_port = 9334;
    config.rpc_user = "flowcoin";
    config.rpc_pass = "";
    config.threads  = 1;

    /* Read config file first (command-line overrides below) */
    read_config_file(&config);

    /* Try cookie auth if no rpcuser/rpcpassword from config */
    static char cookie_user[128];
    static char cookie_pass[128];
    if (config.rpc_pass[0] == '\0' ||
        (strcmp(config.rpc_user, "flowcoin") == 0 && config.rpc_pass[0] == '\0')) {
        const char *home = getenv("HOME");
        if (home) {
            char datadir[512];
            snprintf(datadir, sizeof(datadir), "%s/.flowcoin", home);
            if (rpc_read_cookie(datadir, cookie_user, sizeof(cookie_user),
                                cookie_pass, sizeof(cookie_pass))) {
                config.rpc_user = cookie_user;
                config.rpc_pass = cookie_pass;
            }
        }
    }

    /* Parse command-line arguments */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--rpcuser") == 0) && i + 1 < argc) {
            config.rpc_user = argv[++i];
        } else if ((strcmp(argv[i], "--rpcpassword") == 0) && i + 1 < argc) {
            config.rpc_pass = argv[++i];
        } else if ((strcmp(argv[i], "--rpcport") == 0) && i + 1 < argc) {
            config.rpc_port = atoi(argv[++i]);
        } else if ((strcmp(argv[i], "--rpchost") == 0) && i + 1 < argc) {
            config.rpc_host = argv[++i];
        } else if ((strcmp(argv[i], "--threads") == 0) && i + 1 < argc) {
            config.threads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("FlowCoin Miner v1.0 - Keccak-256d Proof-of-Work\n\n");
            printf("Usage: flowcoin-miner [options]\n\n");
            printf("Options:\n");
            printf("  --rpcuser <user>      RPC username (default: flowcoin)\n");
            printf("  --rpcpassword <pass>  RPC password\n");
            printf("  --rpchost <host>      RPC host (default: 127.0.0.1)\n");
            printf("  --rpcport <port>      RPC port (default: 9334)\n");
            printf("  --threads <n>         CPU threads (default: 1)\n");
            printf("  --help, -h            Show this help\n\n");
            printf("Config is also read from ~/.flowcoin/flowcoin.conf\n");
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s (try --help)\n", argv[i]);
            return 1;
        }
    }

    /* Install signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGWINCH, sig_handler);

    /* Initialize stats */
    memset(&g_stats, 0, sizeof(g_stats));
    g_stats.start_time = time(NULL);
    strncpy(g_stats.rpc_host, config.rpc_host, sizeof(g_stats.rpc_host) - 1);
    g_stats.rpc_port = config.rpc_port;

    /* Initialize TUI */
    init_tui();
    tui_log("FlowCoin Miner v1.0 starting...");
    tui_log("Keccak-256d Proof-of-Work | Solo mining mode");
    tui_log("Connecting to %s:%d...", config.rpc_host, config.rpc_port);

    /* Start mining thread */
    pthread_t miner_tid;
    if (pthread_create(&miner_tid, NULL, mining_thread, &config) != 0) {
        cleanup_tui();
        fprintf(stderr, "Failed to create mining thread\n");
        return 1;
    }

    /* TUI update loop (main thread) */
    while (g_running) {
        if (g_resize) {
            g_resize = 0;
            resize_tui();
        }

        update_tui();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            g_running = 0;
        }

        /* halfdelay(5) in init_tui handles 500ms timing via getch() */
    }

    /* Clean shutdown */
    tui_log("Shutting down...");
    update_tui();
    usleep(200000);

    pthread_join(miner_tid, NULL);
    cleanup_tui();

    printf("\nFlowCoin Miner stopped.\n");
    printf("Total hashes:    %lu\n", (unsigned long)g_stats.total_hashes);
    printf("Blocks found:    %lu\n", (unsigned long)g_stats.blocks_found);
    printf("Blocks rejected: %lu\n", (unsigned long)g_stats.blocks_rejected);

    return 0;
}
