# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license
#
# Each module is its own static library with explicit dependencies.
# Modules are added in dependency order — no circular deps allowed.

# Phase 1
add_subdirectory(core)
add_subdirectory(crypto)

# Phase 2
add_subdirectory(primitives)

# Phase 3
add_subdirectory(consensus)

# Phase 4
add_subdirectory(chain)

# Phase 5
add_subdirectory(mempool)
add_subdirectory(wallet)

# Phase 6
add_subdirectory(net)

# Phase 7
add_subdirectory(mining)
add_subdirectory(rpc)

# Phase 8
add_subdirectory(node)
