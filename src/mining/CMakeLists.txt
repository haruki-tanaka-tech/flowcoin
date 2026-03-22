# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_mining STATIC
    assembler.cpp
)

target_include_directories(flow_mining PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flow_mining PUBLIC flow_chain flow_mempool flow_wallet)

flowcoin_set_warnings(flow_mining)
flowcoin_set_deterministic(flow_mining)
