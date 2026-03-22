# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_mining STATIC
    assembler.cpp
    trainer.cpp
)

target_include_directories(flow_mining PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party/llama.cpp/ggml/include
)
target_link_libraries(flow_mining PUBLIC flow_chain flow_mempool flow_wallet ggml)

flowcoin_set_warnings(flow_mining)
flowcoin_set_deterministic(flow_mining)
