/*
 * rpc.h - JSON-RPC client for FlowCoin solo miner.
 * Uses raw TCP sockets (no libcurl dependency).
 */

#ifndef FLOWCOIN_RPC_H
#define FLOWCOIN_RPC_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char host[64];
    int  port;
    char user[128];
    char pass[128];
} rpc_client_t;

void rpc_init(rpc_client_t *rpc, const char *host, int port,
              const char *user, const char *pass);
void rpc_cleanup(rpc_client_t *rpc);

/*
 * Read cookie authentication from <datadir>/.cookie file.
 * If the file exists and is valid, fills user and pass buffers.
 * Returns true on success.
 */
bool rpc_read_cookie(const char *datadir, char *user, int user_size,
                     char *pass, int pass_size);

/* Get current block count. Returns -1 on error. */
int64_t rpc_getblockcount(rpc_client_t *rpc);

/* Get block template. Fills header (92 bytes), target (32 bytes), nbits, height.
 * Also stores the coinbase_tx internally for later submission.
 * Returns true on success. */
bool rpc_getblocktemplate(rpc_client_t *rpc, uint8_t *header_out,
                          uint8_t *target_out, uint32_t *nbits_out,
                          uint64_t *height_out);

/* Same but with coinbase address for block reward. */
bool rpc_getblocktemplate_addr(rpc_client_t *rpc, uint8_t *header_out,
                          uint8_t *target_out, uint32_t *nbits_out,
                          uint64_t *height_out, const char *coinbase_addr);

/* Get a new address from the wallet. Returns true on success. */
bool rpc_getnewaddress(rpc_client_t *rpc, char *addr_out, int addr_size);

/* Submit a solved block (legacy -- sends only header, kept for compatibility). */
bool rpc_submitblock(rpc_client_t *rpc, const uint8_t *header,
                     int header_len, uint32_t nonce);

/*
 * Submit a complete block with Ed25519 signature and coinbase transaction.
 *
 * Builds the full serialized block:
 *   [92 bytes unsigned header with winning nonce]
 *   [32 bytes miner_pubkey]
 *   [64 bytes ed25519 signature over bytes 0-91]
 *   [CompactSize(1)]
 *   [coinbase_tx bytes from getblocktemplate]
 *
 * Returns true if the node accepts the block.
 */
bool rpc_submitblock_full(rpc_client_t *rpc,
                          const uint8_t *unsigned_header,
                          const uint8_t *miner_privkey,
                          const uint8_t *miner_pubkey);

/* Access the stored coinbase tx from the last getblocktemplate call. */
const uint8_t *rpc_get_coinbase_tx(int *len_out);

#endif /* FLOWCOIN_RPC_H */
