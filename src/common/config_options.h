// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Registration of all supported command-line and config-file options.
// Call register_all_options() early in main() to populate the
// ArgsManager with allowed arguments, categories, and defaults.
//
// This centralizes all option definitions so that:
//   - help text is auto-generated and always up to date
//   - unknown options can be detected and rejected
//   - defaults are documented in a single place

#ifndef FLOWCOIN_COMMON_CONFIG_OPTIONS_H
#define FLOWCOIN_COMMON_CONFIG_OPTIONS_H

namespace flow::common {

class ArgsManager;

/// Register all supported options with the ArgsManager.
/// Must be called before parse_command_line().
void register_all_options(ArgsManager& args);

/// Register chain/consensus options.
void register_chain_options(ArgsManager& args);

/// Register network options.
void register_network_options(ArgsManager& args);

/// Register wallet options.
void register_wallet_options(ArgsManager& args);

/// Register RPC options.
void register_rpc_options(ArgsManager& args);

/// Register mining options.
void register_mining_options(ArgsManager& args);

/// Register debug/test options.
void register_debug_options(ArgsManager& args);

} // namespace flow::common

#endif // FLOWCOIN_COMMON_CONFIG_OPTIONS_H
