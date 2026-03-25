# Deterministic/reproducible build settings
# Ensures same source + same compiler = same binary

# Strip source paths from binary
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.")

# Use SOURCE_DATE_EPOCH for timestamps if set
if(DEFINED ENV{SOURCE_DATE_EPOCH})
    set(SOURCE_DATE_EPOCH $ENV{SOURCE_DATE_EPOCH})
else()
    string(TIMESTAMP SOURCE_DATE_EPOCH "%s" UTC)
endif()

add_compile_definitions(SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH})

# Disable __DATE__ and __TIME__ macros
add_compile_options(-Wno-builtin-macro-redefined)
add_compile_definitions(__DATE__="redacted")
add_compile_definitions(__TIME__="redacted")

# Sort object files for deterministic linking
set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> Dcrs <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Dcrs <TARGET> <LINK_FLAGS> <OBJECTS>")
