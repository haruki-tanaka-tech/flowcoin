# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_consensus STATIC
    params.cpp
    reward.cpp
    difficulty.cpp
    growth.cpp
    validation.cpp
)

target_include_directories(flow_consensus PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flow_consensus PUBLIC flow_core flow_crypto flow_primitives)

flowcoin_set_warnings(flow_consensus)
flowcoin_set_deterministic(flow_consensus)
