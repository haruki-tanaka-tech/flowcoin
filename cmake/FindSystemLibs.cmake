# Find system libraries needed by FlowCoin

# pthreads (required)
find_package(Threads REQUIRED)

# dl (dynamic loading, required on Linux)
if(UNIX AND NOT APPLE)
    find_library(DL_LIBRARY dl)
    if(NOT DL_LIBRARY)
        message(FATAL_ERROR "libdl not found")
    endif()
endif()

# math library
find_library(M_LIBRARY m)

# Check for optional system features
include(CheckFunctionExists)
check_function_exists(mlock HAVE_MLOCK)
check_function_exists(madvise HAVE_MADVISE)
check_function_exists(posix_fadvise HAVE_POSIX_FADVISE)
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
check_function_exists(getifaddrs HAVE_GETIFADDRS)

# Generate config
configure_file(
    ${CMAKE_SOURCE_DIR}/cmake/flowcoin-config.h.in
    ${CMAKE_BINARY_DIR}/flowcoin-config.h
)

# Make config available
include_directories(${CMAKE_BINARY_DIR})
