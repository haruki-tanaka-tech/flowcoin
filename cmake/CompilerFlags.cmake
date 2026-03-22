# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

function(flowcoin_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W3)
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wno-unused-parameter
        )
    endif()
endfunction()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT MSVC)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
