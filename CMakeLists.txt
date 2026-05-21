cmake_minimum_required(VERSION 4.2)
project(computer_network_final_project)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

set(SOURCES
        dns.h
        relay.h
        cache.h
        table.h
        logger.h
        idmap.h
        config.h
        netutil.h
        dns.c
        relay.c
        cache.c
        table.c
        logger.c
        idmap.c
        config.c
        netutil.c
)

add_executable(Main
        src/main.cpp
        ${SOURCES}
)
