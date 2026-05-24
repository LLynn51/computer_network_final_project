cmake_minimum_required(VERSION 3.10)
project(computer_network_final_project C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

set(SOURCES
        src/dns.c
        src/relay.c
        src/cache.c
        src/table.c
        src/logger.c
        src/idmap.c
        src/config.c
        src/netutil.c
)

add_executable(Main
        src/main.c
        ${SOURCES}
)

if (WIN32)
    target_link_libraries(Main ws2_32)
endif()
