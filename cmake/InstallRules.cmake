# Installation rules

include(GNUInstallDirs)

# Binaries
install(TARGETS flowcoind flowcoin-cli flowcoin-tx
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Man pages
install(FILES
    share/flowcoind.1
    share/flowcoin-cli.1
    share/flowcoin-tx.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)

# Config example
install(FILES flowcoin.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/flowcoin
    RENAME flowcoin.conf
)

# Uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY
    )
    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
    )
endif()
