cmake_minimum_required(VERSION 3.15)
project(untitled C)

set(CMAKE_C_STANDARD 99)

include(FindPCAP.cmake)

add_executable(untitled main.c)
target_link_libraries(untitled ${PCAP_LIBRARY})