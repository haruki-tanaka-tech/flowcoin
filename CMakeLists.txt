# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license

cmake_minimum_required(VERSION 3.24)
project(flowcoin VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# CMake modules
include(cmake/CompilerFlags.cmake)
include(cmake/DeterministicBuild.cmake)
include(cmake/FetchDependencies.cmake)

# Third-party vendored libraries
add_subdirectory(third_party)

# FlowCoin source
add_subdirectory(src)

# Tools (executables)
add_subdirectory(tools)

# Tests
option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()
