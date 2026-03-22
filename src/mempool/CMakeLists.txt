# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_mempool STATIC
    mempool.cpp
)

target_include_directories(flow_mempool PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flow_mempool PUBLIC flow_core flow_primitives)

flowcoin_set_warnings(flow_mempool)
flowcoin_set_deterministic(flow_mempool)
