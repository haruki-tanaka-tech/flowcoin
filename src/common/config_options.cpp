// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "common/config_options.h"
#include "common/args.h"

namespace flow::common {

// ============================================================================
// Chain/consensus options
// ============================================================================

void register_chain_options(ArgsManager& args) {
    args.add_arg({"-datadir", "Specify data directory",
                  "General", true, "", false, false});

    args.add_arg({"-conf", "Specify configuration file",
                  "General", true, "flowcoin.conf", false, false});

    args.add_arg({"-testnet", "Use the test chain",
                  "Chain selection", false, "", false, false});

    args.add_arg({"-regtest", "Enter regression test mode",
                  "Chain selection", false, "", false, false});

    args.add_arg({"-assumevalid",
                  "If this block hash is in the chain assume it and its "
                  "ancestors are valid and skip their script verification",
                  "Chain selection", true, "", false, false});

    args.add_arg({"-dbcache", "Maximum database cache size in MB",
                  "General", true, "450", false, false});

    args.add_arg({"-prune", "Reduce storage requirements by pruning "
                  "old blocks. Set target size in MB (0 = disable)",
                  "General", true, "0", false, false});

    args.add_arg({"-reindex", "Rebuild chain state and block index "
                  "from existing block data",
                  "General", false, "", false, false});

    args.add_arg({"-reindex-chainstate",
                  "Rebuild chain state from existing block data",
                  "General", false, "", false, false});

    args.add_arg({"-txindex", "Maintain a full transaction index",
                  "General", false, "", false, false});

    args.add_arg({"-maxmempool", "Maximum mempool size in MB",
                  "General", true, "300", false, false});

    args.add_arg({"-par", "Number of script verification threads "
                  "(0 = auto-detect, -1 = single-threaded)",
                  "General", true, "0", false, false});

    args.add_arg({"-maxorphantx",
                  "Maximum number of orphan transactions to keep in memory",
                  "General", true, "100", false, false});

    args.add_arg({"-blockmaxsize", "Maximum block size in bytes for mining",
                  "General", true, "32000000", false, false});

    args.add_arg({"-checkblocks",
                  "Number of blocks to check at startup",
                  "General", true, "6", false, false});

    args.add_arg({"-checklevel",
                  "Block verification level (0-4, higher is more thorough)",
                  "General", true, "3", false, false});
}

// ============================================================================
// Network options
// ============================================================================

void register_network_options(ArgsManager& args) {
    args.add_arg({"-listen", "Accept connections from outside",
                  "Connection", false, "1", false, false});

    args.add_arg({"-bind", "Bind to given address. Use [host]:port "
                  "for IPv6",
                  "Connection", true, "0.0.0.0", false, false});

    args.add_arg({"-port", "Listen for connections on this port",
                  "Connection", true, "9333", false, false});

    args.add_arg({"-maxconnections", "Maximum number of connections",
                  "Connection", true, "125", false, false});

    args.add_arg({"-maxoutbound",
                  "Maximum number of outbound connections",
                  "Connection", true, "8", false, false});

    args.add_arg({"-addnode", "Add a node to connect to and attempt "
                  "to keep the connection open",
                  "Connection", true, "", false, false});

    args.add_arg({"-connect", "Connect only to the specified node(s). "
                  "Overrides automatic peer discovery",
                  "Connection", true, "", false, false});

    args.add_arg({"-seednode", "Connect to a node to retrieve peer "
                  "addresses, and disconnect",
                  "Connection", true, "", false, false});

    args.add_arg({"-dnsseed", "Query for peer addresses via DNS seeds",
                  "Connection", false, "1", false, false});

    args.add_arg({"-discover", "Discover own IP address",
                  "Connection", false, "1", false, false});

    args.add_arg({"-externalip", "Specify your own public address",
                  "Connection", true, "", false, false});

    args.add_arg({"-onlynet", "Only connect to nodes in network "
                  "(ipv4, ipv6, onion)",
                  "Connection", true, "", false, false});

    args.add_arg({"-timeout", "Connection timeout in milliseconds",
                  "Connection", true, "5000", false, false});

    args.add_arg({"-bantime", "Default ban duration in seconds",
                  "Connection", true, "86400", false, false});

    args.add_arg({"-maxuploadtarget",
                  "Maximum total upload target in MB per 24h "
                  "(0 = unlimited)",
                  "Connection", true, "0", false, false});

    args.add_arg({"-whitelist", "Whitelist peers connecting from "
                  "the given IP or CIDR range",
                  "Connection", true, "", false, false});

    args.add_arg({"-proxy", "Connect through SOCKS5 proxy",
                  "Connection", true, "", false, false});
}

// ============================================================================
// Wallet options
// ============================================================================

void register_wallet_options(ArgsManager& args) {
    args.add_arg({"-disablewallet", "Do not load the wallet",
                  "Wallet", false, "", false, false});

    args.add_arg({"-wallet", "Specify wallet file (within data directory)",
                  "Wallet", true, "wallet.dat", false, false});

    args.add_arg({"-walletbroadcast",
                  "Make the wallet broadcast transactions",
                  "Wallet", false, "1", false, false});

    args.add_arg({"-keypool", "Key pool size",
                  "Wallet", true, "1000", false, false});

    args.add_arg({"-paytxfee", "Fee rate per KB for wallet transactions "
                  "(in FLC)",
                  "Wallet", true, "0.0", false, false});

    args.add_arg({"-mintxfee", "Minimum fee rate per KB for wallet "
                  "transactions (in FLC)",
                  "Wallet", true, "0.00001", false, false});

    args.add_arg({"-maxtxfee", "Maximum fee per transaction "
                  "(in FLC)",
                  "Wallet", true, "0.1", false, false});

    args.add_arg({"-spendzeroconfchange",
                  "Spend unconfirmed change when sending",
                  "Wallet", false, "1", false, false});

    args.add_arg({"-zapwallettxes",
                  "Delete all wallet transactions and only recover "
                  "from the blockchain",
                  "Wallet", false, "", false, false});

    args.add_arg({"-salvagewallet",
                  "Attempt to recover private keys from a corrupt wallet",
                  "Wallet", false, "", false, false});

    args.add_arg({"-upgradewallet",
                  "Upgrade wallet to latest format on startup",
                  "Wallet", false, "", false, false});
}

// ============================================================================
// RPC options
// ============================================================================

void register_rpc_options(ArgsManager& args) {
    args.add_arg({"-server", "Accept command line and JSON-RPC commands",
                  "RPC server", false, "1", false, false});

    args.add_arg({"-rpcbind", "Bind to given address to listen for "
                  "JSON-RPC connections",
                  "RPC server", true, "127.0.0.1", false, false});

    args.add_arg({"-rpcport", "Listen for JSON-RPC connections on this port",
                  "RPC server", true, "9334", false, false});

    args.add_arg({"-rpcuser", "Username for JSON-RPC connections",
                  "RPC server", true, "", false, false});

    args.add_arg({"-rpcpassword", "Password for JSON-RPC connections",
                  "RPC server", true, "", false, false});

    args.add_arg({"-rpcallowip", "Allow JSON-RPC connections from "
                  "specified source. Use CIDR notation",
                  "RPC server", true, "", false, false});

    args.add_arg({"-rpcthreads", "Number of threads to service RPC calls",
                  "RPC server", true, "4", false, false});

    args.add_arg({"-rpcworkqueue",
                  "Depth of the work queue to service RPC calls",
                  "RPC server", true, "16", false, false});

    args.add_arg({"-rpctimeout",
                  "Timeout during HTTP requests (seconds)",
                  "RPC server", true, "30", false, false});

    args.add_arg({"-rpccookiefile",
                  "Location of the auth cookie (default: data dir)",
                  "RPC server", true, "", false, false});

    args.add_arg({"-rpcauth", "Username and hashed password for "
                  "JSON-RPC connections (format: user:salt$hash)",
                  "RPC server", true, "", false, false});
}

// ============================================================================
// Mining options
// ============================================================================

void register_mining_options(ArgsManager& args) {
    args.add_arg({"-gen", "Generate blocks (mining)",
                  "Mining", false, "", false, false});

    args.add_arg({"-genproclimit",
                  "Number of threads for training-based mining "
                  "(-1 = all available)",
                  "Mining", true, "1", false, false});

    args.add_arg({"-mineraddress",
                  "Address to receive mined block rewards",
                  "Mining", true, "", false, false});

    args.add_arg({"-trainingdata",
                  "Path to the training dataset directory",
                  "Mining", true, "", false, false});

    args.add_arg({"-learningrate",
                  "Learning rate for training (fixed-point: 100 = 0.0001)",
                  "Mining", true, "100", false, false});

    args.add_arg({"-batchsize",
                  "Batch size for training (tokens)",
                  "Mining", true, "64", false, false});

    args.add_arg({"-trainepochs",
                  "Maximum training epochs per block attempt",
                  "Mining", true, "10", false, false});

    args.add_arg({"-stratum",
                  "Enable Stratum mining protocol server",
                  "Mining", false, "", false, false});

    args.add_arg({"-stratumport",
                  "Port for Stratum server",
                  "Mining", true, "9335", false, false});

    args.add_arg({"-stratumbind",
                  "Bind address for Stratum server",
                  "Mining", true, "0.0.0.0", false, false});
}

// ============================================================================
// Debug options
// ============================================================================

void register_debug_options(ArgsManager& args) {
    args.add_arg({"-debug", "Output debugging information. "
                  "Specify category or 1 for all",
                  "Debug", true, "", false, false});

    args.add_arg({"-loglevel", "Logging level (trace, debug, info, "
                  "warn, error, fatal)",
                  "Debug", true, "info", false, false});

    args.add_arg({"-logfile", "Specify debug log file",
                  "Debug", true, "debug.log", false, false});

    args.add_arg({"-logtimestamps", "Prepend timestamps to debug output",
                  "Debug", false, "1", false, false});

    args.add_arg({"-logtimemicros", "Add microsecond precision to timestamps",
                  "Debug", false, "", false, false});

    args.add_arg({"-logips", "Include IP addresses in debug output",
                  "Debug", false, "", false, false});

    args.add_arg({"-shrinkdebugfile",
                  "Shrink debug.log file on startup",
                  "Debug", false, "1", false, false});

    args.add_arg({"-printtoconsole", "Send debug output to console "
                  "instead of file",
                  "Debug", false, "", false, false});

    args.add_arg({"-printpriority",
                  "Log transaction fee rate info",
                  "Debug", false, "", false, false});

    args.add_arg({"-limitfreerelay",
                  "Rate-limit free transactions to N KB/min",
                  "Debug", true, "0", false, false});

    args.add_arg({"-checkpoints",
                  "Enable/disable checkpoint enforcement",
                  "Debug", false, "1", false, false});

    args.add_arg({"-dropmessagestest",
                  "Randomly drop 1 in N network messages "
                  "(for testing only)",
                  "Debug", true, "0", true, false});

    args.add_arg({"-stopafterblockimport",
                  "Stop after importing a number of blocks "
                  "(for testing only)",
                  "Debug", false, "", true, false});

    args.add_arg({"-stopatheight",
                  "Stop running after reaching the given height",
                  "Debug", true, "0", true, false});

    args.add_arg({"-mocktime",
                  "Replace actual time with N seconds since epoch "
                  "(for testing only)",
                  "Debug", true, "0", true, false});

    args.add_arg({"-maxtipage",
                  "Maximum tip age in seconds to consider node in "
                  "initial block download",
                  "Debug", true, "86400", false, false});
}

// ============================================================================
// Register all
// ============================================================================

void register_all_options(ArgsManager& args) {
    // General options first
    args.add_arg({"-version", "Print version and exit",
                  "General", false, "", false, false});

    args.add_arg({"-help", "Print this help message and exit",
                  "General", false, "", false, false});

    args.add_arg({"-daemon", "Run in the background as a daemon",
                  "General", false, "", false, false});

    args.add_arg({"-pid", "Specify PID file",
                  "General", true, ".pid", false, false});

    register_chain_options(args);
    register_network_options(args);
    register_wallet_options(args);
    register_rpc_options(args);
    register_mining_options(args);
    register_debug_options(args);
}

} // namespace flow::common
