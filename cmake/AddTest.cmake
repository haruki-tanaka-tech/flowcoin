# Helper to add test targets

function(add_flowcoin_test name)
    add_executable(test_${name} ${ARGN})
    target_link_libraries(test_${name} PRIVATE
        flowcoin_consensus flowcoin_chain flowcoin_net
        flowcoin_wallet flowcoin_rpc flowcoin_primitives
        flowcoin_crypto flowcoin_hash flowcoin_util
        flowcoin_mempool flowcoin_script flowcoin_node
        flowcoin_mining flowcoin_index flowcoin_policy
        flowcoin_interfaces flowcoin_kernel flowcoin_common
        flowcoin_support flowcoin_compat flowcoin_rest
        sqlite ed25519 xkcp zstd uv_a randomx
        Threads::Threads ${DL_LIBRARY} ${M_LIBRARY}
    )
    target_include_directories(test_${name} PRIVATE ${CMAKE_SOURCE_DIR}/src)
    add_test(NAME ${name} COMMAND test_${name})
endfunction()
