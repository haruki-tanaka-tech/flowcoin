# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_chain STATIC
    blockindex.cpp
    utxo.cpp
    blockstore.cpp
    chaindb.cpp
    chainstate.cpp
)

target_include_directories(flow_chain PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flow_chain PUBLIC flow_consensus sqlite3 spdlog::spdlog)

flowcoin_set_warnings(flow_chain)
flowcoin_set_deterministic(flow_chain)
