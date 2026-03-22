# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

function(flowcoin_set_deterministic target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /fp:strict)
    else()
        target_compile_options(${target} PRIVATE -fno-fast-math -ffp-contract=off)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
            target_compile_options(${target} PRIVATE -march=x86-64-v2)
        endif()
    endif()
endfunction()
