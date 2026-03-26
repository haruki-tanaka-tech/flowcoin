/*
 * rpc.c - JSON-RPC client for FlowCoin solo miner.
 * Uses raw TCP sockets -- no libcurl, no jansson.
 */

#include "rpc.h"
#include "keccak2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../crypto/ed25519.h"

/* ─── Stored coinbase tx from getblocktemplate ────────────────────────── */

static uint8_t g_coinbase_tx[4096];
static int     g_coinbase_tx_len = 0;

/* ─── Base64 encoder ─────────────────────────────────────────────────── */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const char *input, char *output, int outsize)
{
    int len = (int)strlen(input);
    int i = 0, j = 0;

    while (i < len && j < outsize - 4) {
        uint32_t octet_a = (i < len) ? (uint8_t)input[i++] : 0;
        uint32_t octet_b = (i < len) ? (uint8_t)input[i++] : 0;
        uint32_t octet_c = (i < len) ? (uint8_t)input[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = b64_table[(triple >> 18) & 0x3F];
        output[j++] = b64_table[(triple >> 12) & 0x3F];

        if (i - 2 <= len)
            output[j++] = b64_table[(triple >> 6) & 0x3F];
        else
            output[j++] = '=';

        if (i - 1 <= len)
            output[j++] = b64_table[triple & 0x3F];
        else
            output[j++] = '=';
    }
    output[j] = '\0';
}

/* ─── Minimal JSON helpers ───────────────────────────────────────────── */

/*
 * Find a JSON string value by key.  Very simplistic -- good enough for
 * well-formed RPC responses.  Returns pointer into buf on success,
 * NULL on failure.
 */
static const char *json_find_string(const char *json, const char *key,
                                    char *buf, int bufsize)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    const char *p = strstr(json, needle);
    if (!p) return NULL;

    p += strlen(needle);
    /* skip whitespace and colon */
    while (*p && (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n'))
        p++;

    if (*p == '"') {
        p++; /* skip opening quote */
        int i = 0;
        while (*p && *p != '"' && i < bufsize - 1) {
            if (*p == '\\' && *(p + 1)) {
                p++; /* skip escape */
            }
            buf[i++] = *p++;
        }
        buf[i] = '\0';
        return buf;
    }

    /* not a string value */
    return NULL;
}

/*
 * Find a JSON integer value by key.
 */
static int64_t json_find_int(const char *json, const char *key)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    const char *p = strstr(json, needle);
    if (!p) return -1;

    p += strlen(needle);
    while (*p && (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n'))
        p++;

    /* could be a number or null */
    if (*p == 'n') return -1; /* null */

    return strtoll(p, NULL, 10);
}

/*
 * Find a JSON object/array value by key.
 * Returns a pointer into the original json (not copied).
 */
static const char *json_find_value(const char *json, const char *key)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    const char *p = strstr(json, needle);
    if (!p) return NULL;

    p += strlen(needle);
    while (*p && (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n'))
        p++;

    return p;
}

/* ─── Hex utilities ──────────────────────────────────────────────────── */

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, int max_bytes)
{
    int i = 0;
    while (hex[0] && hex[1] && i < max_bytes) {
        int hi = hex_val(hex[0]);
        int lo = hex_val(hex[1]);
        if (hi < 0 || lo < 0) break;
        out[i++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return i;
}

static void hex_encode(const uint8_t *data, int len, char *out)
{
    for (int i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

/* ─── TCP / HTTP ─────────────────────────────────────────────────────── */

static int tcp_connect(const char *host, int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        /* Try hostname resolution */
        struct hostent *he = gethostbyname(host);
        if (!he) { close(sock); return -1; }
        memcpy(&addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
    }

    /* Set a 10-second connect timeout */
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

/*
 * Send an HTTP POST with JSON-RPC payload.
 * Returns malloc'd response body (caller frees), or NULL on error.
 */
static char *rpc_call_sized(rpc_client_t *rpc, const char *method,
                            const char *params, int params_len)
{
    /* Build JSON-RPC request body */
    int body_cap = params_len + 256;
    char *body = (char *)malloc((size_t)body_cap);
    if (!body) return NULL;

    int body_len = snprintf(body, (size_t)body_cap,
             "{\"jsonrpc\":\"1.0\",\"id\":\"miner\",\"method\":\"%s\",\"params\":%s}",
             method, params);

    /* Base64-encode credentials */
    char creds[256];
    snprintf(creds, sizeof(creds), "%s:%s", rpc->user, rpc->pass);
    char auth[512];
    base64_encode(creds, auth, sizeof(auth));

    /* Build HTTP request */
    int req_cap = body_len + 512;
    char *request = (char *)malloc((size_t)req_cap);
    if (!request) { free(body); return NULL; }

    int req_len = snprintf(request, (size_t)req_cap,
        "POST / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        rpc->host, rpc->port, auth, body_len, body);

    free(body);

    /* Connect */
    int sock = tcp_connect(rpc->host, rpc->port);
    if (sock < 0) { free(request); return NULL; }

    /* Send */
    if (send(sock, request, (size_t)req_len, 0) != req_len) {
        close(sock);
        free(request);
        return NULL;
    }
    free(request);

    /* Receive response */
    size_t resp_cap = 65536;
    char *resp = (char *)malloc(resp_cap);
    if (!resp) { close(sock); return NULL; }

    size_t resp_len = 0;
    ssize_t n;
    while ((n = recv(sock, resp + resp_len, resp_cap - resp_len - 1, 0)) > 0) {
        resp_len += (size_t)n;
        if (resp_len >= resp_cap - 1) {
            resp_cap *= 2;
            char *tmp = (char *)realloc(resp, resp_cap);
            if (!tmp) { free(resp); close(sock); return NULL; }
            resp = tmp;
        }
    }
    resp[resp_len] = '\0';
    close(sock);

    /* Find the JSON body (after \r\n\r\n) */
    char *json_body = strstr(resp, "\r\n\r\n");
    if (!json_body) {
        free(resp);
        return NULL;
    }
    json_body += 4;

    /* Copy just the body into a new allocation */
    char *result = strdup(json_body);
    free(resp);
    return result;
}

static char *rpc_call(rpc_client_t *rpc, const char *method, const char *params)
{
    return rpc_call_sized(rpc, method, params, (int)strlen(params));
}

/* ─── Public API ─────────────────────────────────────────────────────── */

void rpc_init(rpc_client_t *rpc, const char *host, int port,
              const char *user, const char *pass)
{
    memset(rpc, 0, sizeof(*rpc));
    strncpy(rpc->host, host, sizeof(rpc->host) - 1);
    rpc->port = port;
    strncpy(rpc->user, user, sizeof(rpc->user) - 1);
    strncpy(rpc->pass, pass, sizeof(rpc->pass) - 1);
}

void rpc_cleanup(rpc_client_t *rpc)
{
    (void)rpc;
    /* Nothing to free -- all stack/embedded */
}

int64_t rpc_getblockcount(rpc_client_t *rpc)
{
    char *resp = rpc_call(rpc, "getblockcount", "[]");
    if (!resp) return -1;

    /* The result is a bare integer: {"result":12345,...} */
    int64_t height = json_find_int(resp, "result");
    free(resp);
    return height;
}

bool rpc_getblocktemplate(rpc_client_t *rpc, uint8_t *header_out,
                          uint8_t *target_out, uint32_t *nbits_out,
                          uint64_t *height_out)
{
    char *resp = rpc_call(rpc, "getblocktemplate",
        "[{\"capabilities\":[\"coinbasetxn\",\"workid\",\"coinbase/append\"]}]");
    if (!resp) return false;

    /* Check for error */
    const char *err_check = json_find_value(resp, "error");
    if (err_check && *err_check != 'n') { /* not null */
        free(resp);
        return false;
    }

    /* Parse fields from the result object */
    char prev_hash_hex[128] = {0};
    char bits_hex[32] = {0};
    char target_hex[128] = {0};
    char merkle_root_hex[128] = {0};

    json_find_string(resp, "previousblockhash", prev_hash_hex, sizeof(prev_hash_hex));
    json_find_string(resp, "bits", bits_hex, sizeof(bits_hex));
    json_find_string(resp, "target", target_hex, sizeof(target_hex));
    json_find_string(resp, "merkle_root", merkle_root_hex, sizeof(merkle_root_hex));

    int64_t height = json_find_int(resp, "height");
    int64_t curtime = json_find_int(resp, "curtime");
    int64_t version = json_find_int(resp, "version");

    if (prev_hash_hex[0] == '\0' || bits_hex[0] == '\0' || height < 0) {
        free(resp);
        return false;
    }

    /* ── Extract coinbase transaction and store it ── */
    /* Try coinbase_tx first (our flat format), then coinbasetxn.data */
    char coinbase_hex[8192] = {0};
    if (!json_find_string(resp, "coinbase_tx", coinbase_hex, sizeof(coinbase_hex))
        || coinbase_hex[0] == '\0') {
        /* Fall back to coinbasetxn -> data */
        json_find_string(resp, "data", coinbase_hex, sizeof(coinbase_hex));
    }

    if (coinbase_hex[0] != '\0') {
        g_coinbase_tx_len = hex_decode(coinbase_hex, g_coinbase_tx,
                                       (int)sizeof(g_coinbase_tx));
    } else {
        g_coinbase_tx_len = 0;
    }

    /* Decode previousblockhash (64 hex chars -> 32 bytes, byte-reversed) */
    uint8_t prev_hash[32];
    hex_decode(prev_hash_hex, prev_hash, 32);
    /* Keep as-is — no byte reversal needed */

    /* Use the merkle root provided by the node.
     * The node computes txid = keccak256d(serialize_for_hash(coinbase)), which
     * excludes input signatures.  The miner must NOT recompute this from the
     * raw coinbase bytes (which include signatures) because the result would
     * differ and cause a hash / merkle-root mismatch at validation time. */
    uint8_t merkle_root[32];
    if (merkle_root_hex[0] != '\0') {
        hex_decode(merkle_root_hex, merkle_root, 32);
    } else {
        /* Fallback for older nodes that don't provide merkle_root:
         * hash the full coinbase (will only work if the coinbase has no
         * non-zero signatures, e.g. a fresh coinbase with zeroed sig). */
        if (g_coinbase_tx_len > 0) {
            keccak256d(g_coinbase_tx, (unsigned int)g_coinbase_tx_len, merkle_root);
        } else {
            memset(merkle_root, 0, 32);
        }
    }

    /* Decode nbits */
    uint32_t nbits = (uint32_t)strtoul(bits_hex, NULL, 16);

    /* Build 92-byte unsigned block header:
     *   0-31:  prev_hash (32 bytes)
     *  32-63:  merkle_root (32 bytes)
     *  64-71:  height (uint64 LE, 8 bytes)
     *  72-79:  timestamp (int64 LE, 8 bytes)
     *  80-83:  nbits (uint32 LE, 4 bytes)
     *  84-87:  nonce (uint32 LE, 4 bytes)
     *  88-91:  version (uint32 LE, 4 bytes)
     *  Total: 92 bytes */
    memset(header_out, 0, 92);

    memcpy(header_out + 0, prev_hash, 32);
    memcpy(header_out + 32, merkle_root, 32);
    uint64_t h = (uint64_t)height;
    memcpy(header_out + 64, &h, 8);
    int64_t ts64 = (int64_t)curtime;
    memcpy(header_out + 72, &ts64, 8);
    memcpy(header_out + 80, &nbits, 4);
    uint32_t nonce_init = 0;
    memcpy(header_out + 84, &nonce_init, 4);
    uint32_t ver = (uint32_t)version;
    memcpy(header_out + 88, &ver, 4);

    /* Decode target */
    if (target_hex[0] != '\0') {
        memset(target_out, 0, 32);
        uint8_t target_raw[32];
        int tlen = hex_decode(target_hex, target_raw, 32);
        /* Target from RPC is little-endian display -- reverse to big-endian */
        for (int i = 0; i < tlen && i < 32; i++) {
            target_out[i] = target_raw[31 - i];
        }
    } else {
        /* Compute target from nbits -- big-endian (byte 0 = most significant) */
        memset(target_out, 0, 32);
        uint32_t exp = (nbits >> 24) & 0xFF;
        uint32_t mantissa = nbits & 0x007FFFFF;
        if (exp <= 3) {
            mantissa >>= 8 * (3 - exp);
            target_out[31] = (uint8_t)(mantissa & 0xFF);
            target_out[30] = (uint8_t)((mantissa >> 8) & 0xFF);
            target_out[29] = (uint8_t)((mantissa >> 16) & 0xFF);
        } else {
            /* Big-endian: place mantissa at byte position (32 - exp) */
            int offset = 32 - (int)exp;
            if (offset >= 0 && offset < 30) {
                target_out[offset]     = (uint8_t)((mantissa >> 16) & 0xFF);
                target_out[offset + 1] = (uint8_t)((mantissa >> 8) & 0xFF);
                target_out[offset + 2] = (uint8_t)(mantissa & 0xFF);
            }
        }
    }

    *nbits_out = nbits;
    *height_out = (uint64_t)height;

    free(resp);
    return true;
}

bool rpc_getnewaddress(rpc_client_t *rpc, char *addr_out, int addr_size)
{
    char *resp = rpc_call(rpc, "getnewaddress", "[]");
    if (!resp) return false;

    const char *result = json_find_string(resp, "result", addr_out, addr_size);
    free(resp);
    return result != NULL;
}

bool rpc_submitblock(rpc_client_t *rpc, const uint8_t *header,
                     int header_len, uint32_t nonce __attribute__((unused)))
{
    /* Encode the full header as hex */
    char hex_header[256];
    hex_encode(header, header_len, hex_header);

    /* Build params: ["<hex>"] */
    char params[512];
    snprintf(params, sizeof(params), "[\"%s\"]", hex_header);

    char *resp = rpc_call(rpc, "submitblock", params);
    if (!resp) return false;

    /* submitblock returns null result on success, or an error string */
    const char *p = json_find_value(resp, "result");
    bool ok = (p && *p == 'n'); /* "null" means success */

    free(resp);
    return ok;
}

/* ─── Full block submission with Ed25519 signing ─────────────────────── */

bool rpc_submitblock_full(rpc_client_t *rpc,
                          const uint8_t *unsigned_header,
                          const uint8_t *miner_privkey,
                          const uint8_t *miner_pubkey)
{
    if (g_coinbase_tx_len <= 0) {
        fprintf(stderr, "rpc_submitblock_full: no coinbase tx stored\n");
        return false;
    }

    /*
     * Build the full 188-byte header:
     *   bytes  0- 91: unsigned header (already has winning nonce at offset 84)
     *   bytes 92-123: miner_pubkey (32 bytes)
     *   bytes124-187: miner_sig (64 bytes Ed25519 over bytes 0-91)
     */
    uint8_t full_header[188];
    memcpy(full_header, unsigned_header, 92);
    memcpy(full_header + 92, miner_pubkey, 32);

    /* Sign the unsigned header (bytes 0-91) */
    ed25519_sign(unsigned_header, 92,
                 miner_privkey, miner_pubkey,
                 full_header + 124);

    /*
     * Build the full serialized block:
     *   [188 bytes header]
     *   [CompactSize(1) = 0x01]
     *   [coinbase_tx bytes]
     */
    int block_len = 188 + 1 + g_coinbase_tx_len;
    uint8_t *block_raw = (uint8_t *)malloc((size_t)block_len);
    if (!block_raw) return false;

    memcpy(block_raw, full_header, 188);
    block_raw[188] = 0x01;  /* CompactSize(1) -- one transaction */
    memcpy(block_raw + 189, g_coinbase_tx, (size_t)g_coinbase_tx_len);

    /* Hex-encode the block */
    int hex_len = block_len * 2 + 1;
    char *hex_block = (char *)malloc((size_t)hex_len);
    if (!hex_block) { free(block_raw); return false; }

    hex_encode(block_raw, block_len, hex_block);
    free(block_raw);

    /* Build JSON-RPC params: ["<hex>"]
     * The hex string can be large, so we allocate dynamically. */
    int params_len = hex_len + 4;  /* ["...\0"] */
    char *params = (char *)malloc((size_t)params_len);
    if (!params) { free(hex_block); return false; }

    snprintf(params, (size_t)params_len, "[\"%s\"]", hex_block);
    free(hex_block);

    char *resp = rpc_call_sized(rpc, "submitblock", params, params_len);
    free(params);

    if (!resp) return false;

    /* submitblock returns null result on success, or an error string */
    const char *p = json_find_value(resp, "result");
    bool ok = (p && *p == 'n'); /* "null" means success */

    if (!ok) {
        /* Print rejection reason for debugging */
        char reason[256] = {0};
        json_find_string(resp, "result", reason, sizeof(reason));
        if (reason[0])
            fprintf(stderr, "submitblock rejected: %s\n", reason);

        /* Also check error field */
        char err_msg[512] = {0};
        json_find_string(resp, "message", err_msg, sizeof(err_msg));
        if (err_msg[0])
            fprintf(stderr, "submitblock error: %s\n", err_msg);
    }

    free(resp);
    return ok;
}

const uint8_t *rpc_get_coinbase_tx(int *len_out)
{
    if (len_out) *len_out = g_coinbase_tx_len;
    return g_coinbase_tx;
}
