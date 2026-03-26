/*
 * mining.h - Mining engine header for FlowCoin solo miner.
 */

#ifndef FLOWCOIN_MINING_H
#define FLOWCOIN_MINING_H

#include <stdint.h>
#include <time.h>

typedef struct {
    const char *rpc_host;
    int         rpc_port;
    const char *rpc_user;
    const char *rpc_pass;
    int         threads;
} miner_config_t;

typedef struct {
    double   hashrate_5s;
    double   hashrate_avg;
    uint64_t total_hashes;
    uint64_t blocks_found;
    uint64_t blocks_rejected;
    uint64_t current_height;
    uint32_t difficulty;
    uint64_t best_share;
    double   elapsed_secs;
    time_t   start_time;
    char     rpc_host[64];
    int      rpc_port;
    char     best_hash[128];
} mining_stats_t;

/*
 * Format a hashrate for display.
 * Produces strings like "123.45 KH/s", "1.23 MH/s", "4.56 GH/s".
 */
void format_hashrate(double hr, char *buf, int bufsize);

#endif /* FLOWCOIN_MINING_H */
