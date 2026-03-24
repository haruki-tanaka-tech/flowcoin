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
void test_growth();
void test_validation();
void test_merkle();
void test_serialize();
void test_delta();
void test_mempool();
void test_script();
void test_consensus_model();
void test_eval_engine();
void test_txindex();
void test_sync();
void test_fee_estimator();
void test_txbuilder();
void test_walletutil();
void test_banman();

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
        {"growth", test_growth},
        {"validation", test_validation},
        {"merkle", test_merkle},
        {"serialize", test_serialize},
        {"delta", test_delta},
        {"mempool", test_mempool},
        {"script", test_script},
        {"consensus_model", test_consensus_model},
        {"eval_engine", test_eval_engine},
        {"txindex", test_txindex},
        {"sync", test_sync},
        {"fee_estimator", test_fee_estimator},
        {"txbuilder", test_txbuilder},
        {"walletutil", test_walletutil},
        {"banman", test_banman},
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
