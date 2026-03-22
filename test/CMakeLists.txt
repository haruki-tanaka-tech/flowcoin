# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

# Tests are added per-phase as modules become available.
# Each test file links only the libraries it needs.

# Phase 1
add_executable(test_hash test_hash.cpp)
target_link_libraries(test_hash PRIVATE flow_core GTest::gtest_main)
add_test(NAME test_hash COMMAND test_hash)

add_executable(test_keys test_keys.cpp)
target_link_libraries(test_keys PRIVATE flow_crypto GTest::gtest_main)
add_test(NAME test_keys COMMAND test_keys)

add_executable(test_address test_address.cpp)
target_link_libraries(test_address PRIVATE flow_crypto GTest::gtest_main)
add_test(NAME test_address COMMAND test_address)

# Phase 2
add_executable(test_block test_block.cpp)
target_link_libraries(test_block PRIVATE flow_primitives GTest::gtest_main)
add_test(NAME test_block COMMAND test_block)

# Phase 3
add_executable(test_validation test_validation.cpp)
target_link_libraries(test_validation PRIVATE flow_consensus GTest::gtest_main)
add_test(NAME test_validation COMMAND test_validation)

# Phase 4
add_executable(test_chain test_chain.cpp)
target_link_libraries(test_chain PRIVATE flow_chain GTest::gtest_main)
add_test(NAME test_chain COMMAND test_chain)

# Phase 5
add_executable(test_mempool test_mempool.cpp)
target_link_libraries(test_mempool PRIVATE flow_mempool GTest::gtest_main)
add_test(NAME test_mempool COMMAND test_mempool)

add_executable(test_wallet test_wallet.cpp)
target_link_libraries(test_wallet PRIVATE flow_wallet GTest::gtest_main)
add_test(NAME test_wallet COMMAND test_wallet)

# Phase 6
add_executable(test_net test_net.cpp)
target_link_libraries(test_net PRIVATE flow_net GTest::gtest_main)
add_test(NAME test_net COMMAND test_net)

# Phase 7 — ggml training
add_executable(test_trainer test_trainer.cpp)
target_link_libraries(test_trainer PRIVATE flow_mining GTest::gtest_main)
add_test(NAME test_trainer COMMAND test_trainer)
