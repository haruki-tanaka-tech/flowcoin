# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_net STATIC
    protocol.cpp
    peer.cpp
    netman.cpp
    messages.cpp
)

target_include_directories(flow_net PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flow_net PUBLIC flow_chain flow_mempool uv_a spdlog::spdlog)

flowcoin_set_warnings(flow_net)
flowcoin_set_deterministic(flow_net)
