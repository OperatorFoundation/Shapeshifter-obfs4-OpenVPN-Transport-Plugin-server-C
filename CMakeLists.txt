cmake_minimum_required(VERSION 3.10)
project(shapeshifter-obfs4-server C)

set(CMAKE_C_STANDARD 11)

include_directories(include)
include_directories(src)

add_library(shapeshifter-obfs4-server SHARED
        include/openvpn/openvpn-plugin.h
        include/openvpn/openvpn-vsocket.h
        include/shapeshifter-obfs4-server-go.h
        src/shapeshifter-obfs4-posix.c
        src/shapeshifter-obfs4.c
        src/shapeshifter-obfs4.h)

find_library(CGOLIB NAMES shapeshifter-obfs4-server-go.a shapeshifter-obfs4-server-go HINTS /root/Shapeshifter-OpenVPN/transports/obfs4/shapeshifter-obfs4-server-1.0/lib)
target_link_libraries(shapeshifter-obfs4-server ${CGOLIB})

install(TARGETS shapeshifter-obfs4-server LIBRARY DESTINATION lib)
