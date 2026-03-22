# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_node STATIC
    context.cpp
)

target_include_directories(flow_node PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flow_node PUBLIC flow_rpc flow_net flow_wallet)

flowcoin_set_warnings(flow_node)
flowcoin_set_deterministic(flow_node)
