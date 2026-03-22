# XKCP — Keccak-256 (KeccakP-1600, reference 64-bit)
# CC0 public domain

add_library(xkcp STATIC
    KeccakSponge.c
    KeccakHash.c
    KeccakP-1600-reference.c
)
target_include_directories(xkcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# Suppress warnings in third-party code
target_compile_options(xkcp PRIVATE -w)
