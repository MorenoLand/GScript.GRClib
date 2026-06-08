cmake_minimum_required(VERSION 3.10)
project(grclib VERSION 1.0.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SOURCES
    src/grclib.cpp
    deps/bzip2/src/bzlib.c
    deps/bzip2/src/blocksort.c
    deps/bzip2/src/compress.c
    deps/bzip2/src/decompress.c
    deps/bzip2/src/huffman.c
    deps/bzip2/src/crctable.c
    deps/bzip2/src/randtable.c
)
set(HEADERS include/grclib.h include/IEnums.h)
add_library(grclib SHARED ${SOURCES} ${HEADERS})
target_include_directories(grclib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/miniz/include
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/bzip2/include
)
if(WIN32)
    target_link_libraries(grclib PRIVATE ws2_32 advapi32 iphlpapi)
    target_compile_definitions(grclib PRIVATE GRCLIB_EXPORTS)
endif()
if(APPLE)
    target_link_libraries(grclib PRIVATE "-framework CoreFoundation" "-framework IOKit")
endif()
# add_library(grclib_static STATIC ${SOURCES} ${HEADERS})
# target_include_directories(grclib_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
# if(WIN32)
#     target_link_libraries(grclib_static PRIVATE ws2_32)
# endif()
set(GRCLIB_OUTPUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/bin")
set_target_properties(grclib PROPERTIES
    OUTPUT_NAME grclib
    PREFIX ""
    RUNTIME_OUTPUT_DIRECTORY "${GRCLIB_OUTPUT_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${GRCLIB_OUTPUT_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${GRCLIB_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${GRCLIB_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${GRCLIB_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${GRCLIB_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${GRCLIB_OUTPUT_DIR}"
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "${GRCLIB_OUTPUT_DIR}"
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "${GRCLIB_OUTPUT_DIR}"
    LIBRARY_OUTPUT_DIRECTORY_RELWITHDEBINFO "${GRCLIB_OUTPUT_DIR}"
    LIBRARY_OUTPUT_DIRECTORY_MINSIZEREL "${GRCLIB_OUTPUT_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${GRCLIB_OUTPUT_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${GRCLIB_OUTPUT_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO "${GRCLIB_OUTPUT_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL "${GRCLIB_OUTPUT_DIR}"
)
# set_target_properties(grclib_static PROPERTIES OUTPUT_NAME grclib)
install(TARGETS grclib LIBRARY DESTINATION lib ARCHIVE DESTINATION lib RUNTIME DESTINATION bin)
install(FILES ${HEADERS} DESTINATION include)
