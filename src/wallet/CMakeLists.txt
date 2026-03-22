# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_wallet STATIC
    wallet.cpp
    coinselect.cpp
)

target_include_directories(flow_wallet PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flow_wallet PUBLIC flow_crypto flow_primitives sqlite3)

flowcoin_set_warnings(flow_wallet)
flowcoin_set_deterministic(flow_wallet)
