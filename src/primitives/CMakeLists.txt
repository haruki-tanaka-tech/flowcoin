# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_primitives STATIC
    block.cpp
    transaction.cpp
    delta.cpp
)

target_include_directories(flow_primitives PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flow_primitives PUBLIC flow_core flow_crypto)

flowcoin_set_warnings(flow_primitives)
flowcoin_set_deterministic(flow_primitives)
