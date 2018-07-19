cmake_minimum_required(VERSION 3.10)
project(Shapeshifter_obfs4_OpenVPN_Transport_Plugin_C C)

set(CMAKE_C_STANDARD 11)

include_directories(OpenVPN-Files)
include_directories(Shapeshifter-obfs4-OpenVPN-Transport-Plugin-C)

add_executable(Shapeshifter_obfs4_OpenVPN_Transport_Plugin_C
        OpenVPN-Files/openvpn-plugin.h
        OpenVPN-Files/openvpn-vsocket.h
        Shapeshifter-obfs4-OpenVPN-Transport-Plugin-C/main.c
        Shapeshifter-obfs4-OpenVPN-Transport-Plugin-C/README.shapeshifter-obfs4
        Shapeshifter-obfs4-OpenVPN-Transport-Plugin-C/Shapeshifter-obfs4-OpenVPN-Transport-Plugin.h
        Shapeshifter-obfs4-OpenVPN-Transport-Plugin-C/Shapeshifter-obfs4-OpenVPN-Transport-Plugin.so
        Shapeshifter-obfs4-OpenVPN-Transport-Plugin-C/shapeshifter-obfs4-win32.c
        Shapeshifter-obfs4-OpenVPN-Transport-Plugin-C/shapeshifter-obfs4.c
        Shapeshifter-obfs4-OpenVPN-Transport-Plugin-C/shapeshifter-obfs4.h)
