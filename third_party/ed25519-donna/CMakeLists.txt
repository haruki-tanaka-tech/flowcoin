# ed25519-donna — Ed25519 sign/verify
# Public domain by Andrew M.

add_library(ed25519_donna STATIC ed25519.c)
target_include_directories(ed25519_donna PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(ed25519_donna PRIVATE
    ED25519_REFHASH           # Use built-in SHA-512 (no OpenSSL)
    ED25519_CUSTOMRANDOM      # Use our getrandom() wrapper
    ED25519_FORCE_32BIT       # Force portable 32-bit implementation
)
# Suppress warnings in third-party code
target_compile_options(ed25519_donna PRIVATE -w)
