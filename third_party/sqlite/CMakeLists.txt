# SQLite — embedded database (amalgamation)
# Public domain

add_library(sqlite3 STATIC sqlite3.c)
target_include_directories(sqlite3 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(sqlite3 PRIVATE
    SQLITE_THREADSAFE=1
    SQLITE_DQS=0
    SQLITE_DEFAULT_MEMSTATUS=0
    SQLITE_DEFAULT_WAL_SYNCHRONOUS=1
    SQLITE_OMIT_DECLTYPE
    SQLITE_OMIT_DEPRECATED
)
find_package(Threads REQUIRED)
target_link_libraries(sqlite3 PRIVATE ${CMAKE_DL_LIBS} Threads::Threads)
# Suppress warnings in third-party code
target_compile_options(sqlite3 PRIVATE -w)
