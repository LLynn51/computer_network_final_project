cmake_minimum_required(VERSION 3.10)
project(computer_network_final_project C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include)

set(COMMON_SOURCES
        src/dns.c
        src/logger.c
        src/netutil.c
)

set(SERVER_SOURCES
        src/relay.c
        src/cache.c
        src/table.c
        src/idmap.c
        src/config.c
)

add_executable(Main
        src/main.c
        ${COMMON_SOURCES}
        ${SERVER_SOURCES}
)

add_executable(Client
        src/client.c
        ${COMMON_SOURCES}
)

if (WIN32)
    target_link_libraries(Main ws2_32)
    target_link_libraries(Client ws2_32)
endif()
