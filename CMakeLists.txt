cmake_minimum_required(VERSION 3.10)
project(Shapeshifter_obfs4_OpenVPN_Transport_Plugin_C C)

set(CMAKE_C_STANDARD 11)

include_directories(OpenVPN-Files)
include_directories(Shapeshifter-obfs4-OpenVPN-Transport-Plugin-server-C)

add_library(Shapeshifter_obfs4_OpenVPN_Transport_Plugin_C SHARED
        OpenVPN-Files/openvpn-plugin.h
        OpenVPN-Files/openvpn-vsocket.h
        Shapeshifter-obfs4-OpenVPN-Transport-Plugin-server-C/Shapeshifter-obfs4-OpenVPN-Transport-Plugin.h
        Shapeshifter-obfs4-OpenVPN-Transport-Plugin-server-C/shapeshifter-obfs4-win32.c
        Shapeshifter-obfs4-OpenVPN-Transport-Plugin-server-C/shapeshifter-obfs4.c
        Shapeshifter-obfs4-OpenVPN-Transport-Plugin-server-C/shapeshifter-obfs4.h)

#add_library(CGOLIB SHARED
#        Shapeshifter-obfs4-OpenVPN-Transport-Plugin.h
#        Shapeshifter-obfs4-OpenVPN-Transport-Plugin.lib
#        Shapeshifter-obfs4-OpenVPN-Transport-Plugin.so)
#
#set_target_properties(CGOLIB PROPERTIES LINKER_LANGUAGE C)
#
#target_link_libraries(OpenVPN_Transport_Shapeshifter_Obfs4_C wsock32 ws2_32)
#target_link_libraries(OpenVPN_Transport_Shapeshifter_Obfs4_C CGOLIB)

find_library(CGOLIB Shapeshifter-obfs4-OpenVPN-Transport-Plugin HINTS C:/Users/GCR/CLionProjects/OpenVPN-Transport-Shapeshifter-Obfs4-C)

target_link_libraries(Shapeshifter_obfs4_OpenVPN_Transport_Plugin_C wsock32 ws2_32 ${CGOLIB})