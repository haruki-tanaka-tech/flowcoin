# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

add_library(flow_crypto STATIC
    keys.cpp
    sign.cpp
    hmac_sha512.cpp
    hd.cpp
    address.cpp
)

target_include_directories(flow_crypto PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flow_crypto PUBLIC flow_core ed25519_donna)

flowcoin_set_warnings(flow_crypto)
flowcoin_set_deterministic(flow_crypto)
