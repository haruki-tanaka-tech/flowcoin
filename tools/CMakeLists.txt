# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_executable(flowcoind flowcoind.cpp)
target_link_libraries(flowcoind PRIVATE flow_node spdlog::spdlog)

add_executable(flowcoin-cli flowcoin-cli.cpp)
target_link_libraries(flowcoin-cli PRIVATE nlohmann_json::nlohmann_json)

# flowminer is Python: tools/flowminer.py
# Requires: pip install torch
