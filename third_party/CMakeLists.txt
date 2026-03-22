# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license
#
# Third-party vendored libraries

# Ed25519 signing/verification (public domain)
add_subdirectory(ed25519-donna)

# Keccak-256 hashing (CC0)
add_subdirectory(xkcp)

# SQLite embedded database (public domain)
add_subdirectory(sqlite)

# llama.cpp + ggml (MIT) — for model inference (not training)
# Training uses PyTorch via flowminer.py
# Inference uses ggml/llama.cpp for on-device model execution
# Uncomment when inference integration is ready:
# set(LLAMA_BUILD_TESTS OFF CACHE BOOL "" FORCE)
# set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
# set(LLAMA_BUILD_SERVER OFF CACHE BOOL "" FORCE)
# set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
# add_subdirectory(llama.cpp)
