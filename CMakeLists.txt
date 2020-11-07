cmake_minimum_required(VERSION 3.8)

project(PanStack)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -lpthread -O0 -Wall -Wextra -Wconversion -ggdb3 -DZDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -lpthread -O2 -Wall -Wextra -Wconversion")

include(findpcap/findpcap.cmake)
include_directories(PUBLIC "${PROJECT_SOURCE_DIR}")

add_library(link src/core_data.cpp src/device.cpp src/packetio.cpp)
target_link_libraries(link PUBLIC ${PCAP_LIBRARY})

add_subdirectory(test)