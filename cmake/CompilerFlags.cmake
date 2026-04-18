# Compiler warning and optimization flags

include(CheckCXXCompilerFlag)

# Base flags
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Warning flags
add_compile_options(-Wall -Wextra -Wpedantic)
add_compile_options(-Werror=return-type)
add_compile_options(-Wno-unused-parameter)
add_compile_options(-Wno-missing-field-initializers)

# CRITICAL: No -ffast-math — breaks IEEE 754 determinism.
# RandomX executes IEEE-754 double-precision float ops as part of each
# hash, with a deterministic rounding mode. Every node must get
# bit-identical results or the chain forks.

# Security flags
add_compile_options(-fstack-protector-strong)
add_compile_options(-D_FORTIFY_SOURCE=2)

# Position independent code (required for shared libraries)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Release optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2)
    add_compile_options(-DNDEBUG)
endif()

# Debug flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

# RelWithDebInfo
if(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    add_compile_options(-O2 -g)
endif()

# Check for optional flags
check_cxx_compiler_flag(-Wthread-safety HAS_THREAD_SAFETY)
if(HAS_THREAD_SAFETY)
    add_compile_options(-Wthread-safety)
endif()

# Link-time optimization (optional)
option(ENABLE_LTO "Enable link-time optimization" OFF)
if(ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT lto_supported)
    if(lto_supported)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
endif()

# Deterministic build
option(DETERMINISTIC_BUILD "Enable deterministic build flags" OFF)
if(DETERMINISTIC_BUILD)
    add_compile_options(-frandom-seed=flowcoin)
    add_compile_options(-fno-guess-branch-probability)
endif()
