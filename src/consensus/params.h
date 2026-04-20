// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Consensus parameters for the FlowCoin network.
// Every constant is derived and documented. Modeled after Bitcoin Core's
// consensus/params.h with RandomX Proof-of-Work.

#ifndef FLOWCOIN_CONSENSUS_PARAMS_H
#define FLOWCOIN_CONSENSUS_PARAMS_H

#include <cstdint>
#include <cstddef>

namespace flow::consensus {

// ---- Network Identity -------------------------------------------------------

// ASCII "FLOW" = 0x46('F') 0x4C('L') 0x4F('O') 0x57('W')
constexpr uint32_t MAINNET_MAGIC       = 0x464C4F57;
// ASCII "TFLW" = 0x54('T') 0x46('F') 0x4C('L') 0x57('W')
constexpr uint32_t TESTNET_MAGIC       = 0x54464C57;
// ASCII "RFLW" = 0x52('R') 0x46('F') 0x4C('L') 0x57('W')
constexpr uint32_t REGTEST_MAGIC       = 0x52464C57;

constexpr uint16_t MAINNET_PORT        = 9333;
constexpr uint16_t MAINNET_RPC_PORT    = 9334;
constexpr uint16_t TESTNET_PORT        = 19333;
constexpr uint16_t TESTNET_RPC_PORT    = 19334;
constexpr uint16_t REGTEST_PORT        = 29333;
constexpr uint16_t REGTEST_RPC_PORT    = 29334;

constexpr const char* MAINNET_HRP      = "fl";
constexpr const char* TESTNET_HRP      = "tfl";
constexpr const char* REGTEST_HRP      = "rfl";

// Bitcoin-Core-compatible numeric values so version/nServices fields read
// out naturally in tooling. 70016 = wtxidrelay-era; 31800 = BIP14 floor.
constexpr uint32_t PROTOCOL_VERSION     = 70016;
constexpr uint32_t MIN_PROTOCOL_VERSION = 31800;

// BIP-44 coin type for HD derivation path: m/44'/9555'/...
constexpr uint32_t BIP44_COIN_TYPE     = 9555;

// ---- Monetary Policy (identical to Bitcoin) ---------------------------------

constexpr int64_t  COIN                = 100'000'000LL;
constexpr int64_t  MAX_SUPPLY          = 21'000'000LL * COIN;
constexpr int64_t  INITIAL_REWARD      = 50LL * COIN;
constexpr int      HALVING_INTERVAL    = 210'000;
constexpr int64_t  MIN_REWARD          = 1LL;

// ---- Timing -----------------------------------------------------------------

constexpr int64_t  TARGET_BLOCK_TIME   = 600;    // 10 minutes
constexpr int64_t  MAX_FUTURE_TIME     = 7200;   // 2 hours

// ---- Difficulty (Bitcoin's algorithm) ---------------------------------------

constexpr int      RETARGET_INTERVAL   = 2016;
constexpr int64_t  RETARGET_TIMESPAN   = RETARGET_INTERVAL * TARGET_BLOCK_TIME;
constexpr int      MAX_RETARGET_FACTOR = 4;

// powLimit expressed as compact nBits — the easiest target the network
// ever accepts (difficulty retargets up from here but never below).
// Same value as Bitcoin's difficulty=1: target = 0xffff * 256^26 ≈ 2^224.
//
// The target is hash-function independent — a 256-bit PoW output is treated
// as a uniform random integer regardless of whether it came from SHA-256d
// or RandomX. What differs is the wall-clock time to reach the target:
//
//   RandomX @ 1500 H/s per CPU core
//     → expected 2^32 hashes per block at difficulty 1
//     → solo single-core: ~33 days per block (bootstrap is slow)
//     → 100 CPU cores (150 kH/s): ~8 hours per block
//     → ~4000 cores (6 MH/s) give the 10-minute target
//
// Blocks before the first retarget (2016 blocks, 14 days at target) will
// be much slower until enough miners join. This is the intended behaviour:
// the network floor catches up with hashrate rather than the other way.
constexpr uint32_t INITIAL_NBITS       = 0x1d00ffff;

// ---- Block Limits -----------------------------------------------------------

constexpr size_t   MAX_BLOCK_SIZE      = 32'000'000;
constexpr size_t   MAX_TX_SIZE         = 1'000'000;
constexpr int      MAX_BLOCK_SIGOPS    = 80'000;
constexpr int      COINBASE_MATURITY   = 100;

// ---- Network Limits ---------------------------------------------------------

constexpr int      MAX_OUTBOUND_PEERS  = 8;
constexpr int      MAX_INBOUND_PEERS   = 117;
constexpr int      MAX_PEERS           = MAX_OUTBOUND_PEERS + MAX_INBOUND_PEERS;
constexpr int      FINALITY_DEPTH      = 6;
constexpr int      MAX_INV_SIZE        = 50000;
constexpr int      ADDR_RELAY_MAX      = 1000;

// ---- Cryptography -----------------------------------------------------------

// Keccak padding byte: 0x01 for original Keccak (not SHA-3's 0x06).
constexpr uint8_t  KECCAK_PAD          = 0x01;

// ---- Pruning Configuration --------------------------------------------------

constexpr uint64_t MIN_BLOCKS_TO_KEEP     = 288;
constexpr uint64_t DEFAULT_PRUNE_TARGET_MB = 550;

// ---- Initial Block Download (IBD) ------------------------------------------

constexpr uint64_t IBD_MIN_BLOCKS_BEHIND  = 144;
constexpr int      MAX_HEADERS_RESULTS    = 2000;
constexpr int      MAX_BLOCKS_IN_TRANSIT  = 16;
constexpr int      BLOCK_DOWNLOAD_TIMEOUT = 60;

// ---- Mempool Limits ---------------------------------------------------------

constexpr size_t   MAX_MEMPOOL_SIZE       = 300'000'000;
constexpr int64_t  MIN_RELAY_FEE          = 1000;
constexpr int64_t  MEMPOOL_EXPIRY         = 1'209'600;

// ---- Genesis Block ----------------------------------------------------------

constexpr int64_t  GENESIS_TIMESTAMP   = 1742515200;  // 21/Mar/2026

constexpr const char* GENESIS_COINBASE_MSG =
    "White House calls for federal AI law to preempt states "
    "21/Mar/2026 - FlowCoin: decentralized proof-of-work";

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_PARAMS_H
