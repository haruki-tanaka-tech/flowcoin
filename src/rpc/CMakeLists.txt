# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_rpc STATIC
    server.cpp
    methods.cpp
    http_server.cpp
)

target_include_directories(flow_rpc PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flow_rpc PUBLIC
    flow_chain flow_mempool flow_wallet
    nlohmann_json::nlohmann_json uv_a spdlog::spdlog
)

flowcoin_set_warnings(flow_rpc)
flowcoin_set_deterministic(flow_rpc)
