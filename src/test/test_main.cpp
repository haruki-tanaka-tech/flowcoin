// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include <iostream>
#include <cassert>
#include <cstring>
#include <functional>
#include <vector>
#include <string>

// Forward declarations of all test functions
void test_keccak();
void test_arith_uint256();
void test_ed25519();
void test_slip0010();
void test_bech32();
void test_block_header();
void test_transaction();
void test_difficulty();
void test_reward();
void test_merkle();
void test_serialize();
void test_delta();
void test_mempool();
void test_script();
void test_txindex();
void test_sync();
void test_fee_estimator();
void test_txbuilder();
void test_walletutil();
void test_banman();
void test_encryption();
void test_keypool();
void test_chaindb();
void test_rpc();
void test_reorg();
void test_compact_blocks();
void test_netaddress();
void test_wallet_full();
void test_coin_selection();
void test_strencodings();
void test_transaction_ext();
void test_backup();
void test_threadpool();
void test_fs();
void test_logging();
void test_random();
void test_system();
void test_config();
void test_init();
void test_compact_size();
void test_delta_full();
void test_aes256();
void test_bloom();
void test_script_interpreter();
void test_mempool_advanced();
void test_coinselect_algorithms();
void test_hdchain();
void test_walletdb_full();
void test_rpc_handlers();
void test_policy();
void test_network_full();
void test_bandwidth();
void test_wallet_advanced();
void test_http_parser();
void test_peer_scoring();

struct TestCase {
    std::string name;
    std::function<void()> func;
};

int main() {
    std::vector<TestCase> tests = {
        {"keccak256", test_keccak},
        {"arith_uint256", test_arith_uint256},
        {"ed25519", test_ed25519},
        {"slip0010", test_slip0010},
        {"bech32", test_bech32},
        {"block_header", test_block_header},
        {"transaction", test_transaction},
        {"difficulty", test_difficulty},
        {"reward", test_reward},
        {"merkle", test_merkle},
        {"serialize", test_serialize},
        {"delta", test_delta},
        {"mempool", test_mempool},
        {"script", test_script},
        {"txindex", test_txindex},
        {"sync", test_sync},
        {"fee_estimator", test_fee_estimator},
        {"txbuilder", test_txbuilder},
        {"walletutil", test_walletutil},
        {"banman", test_banman},
        {"encryption", test_encryption},
        {"keypool", test_keypool},
        {"chaindb", test_chaindb},
        {"rpc", test_rpc},
        {"reorg", test_reorg},
        {"compact_blocks", test_compact_blocks},
        {"netaddress", test_netaddress},
        {"wallet_full", test_wallet_full},
        {"coin_selection", test_coin_selection},
        {"strencodings", test_strencodings},
        {"transaction_ext", test_transaction_ext},
        {"backup", test_backup},
        {"threadpool", test_threadpool},
        {"fs", test_fs},
        {"logging_ext", test_logging},
        {"random", test_random},
        {"system", test_system},
        {"config", test_config},
        {"init", test_init},
        {"compact_size", test_compact_size},
        {"delta_full", test_delta_full},
        {"aes256", test_aes256},
        {"bloom", test_bloom},
        {"script_interpreter", test_script_interpreter},
        {"mempool_advanced", test_mempool_advanced},
        {"coinselect_algorithms", test_coinselect_algorithms},
        {"hdchain", test_hdchain},
        {"walletdb_full", test_walletdb_full},
        {"rpc_handlers", test_rpc_handlers},
        {"policy", test_policy},
        {"network_full", test_network_full},
        {"bandwidth", test_bandwidth},
        {"wallet_advanced", test_wallet_advanced},
        {"http_parser", test_http_parser},
        {"peer_scoring", test_peer_scoring},
    };

    int passed = 0, failed = 0;
    for (auto& tc : tests) {
        std::cout << "  TEST " << tc.name << " ... " << std::flush;
        try {
            tc.func();
            std::cout << "OK" << std::endl;
            passed++;
        } catch (const std::exception& e) {
            std::cout << "FAILED: " << e.what() << std::endl;
            failed++;
        } catch (...) {
            std::cout << "FAILED (unknown exception)" << std::endl;
            failed++;
        }
    }

    std::cout << "\nResults: " << passed << " passed, " << failed << " failed, "
              << tests.size() << " total" << std::endl;
    return failed > 0 ? 1 : 0;
}
