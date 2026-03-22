# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_core STATIC
    hash.cpp
    time.cpp
)

target_include_directories(flow_core PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flow_core PUBLIC xkcp)

flowcoin_set_warnings(flow_core)
flowcoin_set_deterministic(flow_core)
