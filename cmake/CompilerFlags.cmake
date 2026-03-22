# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

# Strict warnings applied ONLY to our own targets via this function.
# Third-party code compiles with -w (no warnings).
function(flowcoin_set_warnings target)
    target_compile_options(${target} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wno-unused-parameter
    )
endfunction()

# Debug: sanitizers (global is fine, applies to all)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
