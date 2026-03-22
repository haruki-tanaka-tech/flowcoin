# ed25519-donna — Ed25519 sign/verify
# Public domain by Andrew M.

add_library(ed25519_donna STATIC ed25519.c)
target_include_directories(ed25519_donna PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(ed25519_donna PRIVATE
    ED25519_REFHASH
    ED25519_CUSTOMRANDOM
    ED25519_FORCE_32BIT
)
target_compile_options(ed25519_donna PRIVATE -w)

if(APPLE)
    target_link_libraries(ed25519_donna PRIVATE "-framework Security")
endif()
if(WIN32)
    target_link_libraries(ed25519_donna PRIVATE bcrypt)
endif()
