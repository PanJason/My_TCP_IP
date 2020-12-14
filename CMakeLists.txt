cmake_minimum_required(VERSION 3.8)

project(PanStack)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -lpthread -O0 -Wall -Wextra -Wconversion -ggdb3 -DZDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -lpthread -O2 -Wall -Wextra -Wconversion")
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

include(findpcap/findpcap.cmake)
include_directories(PUBLIC "${PROJECT_SOURCE_DIR}")

add_library(link src/core_data.cpp src/device.cpp src/packetio.cpp src/ip.cpp src/socket.cpp src/tcp.cpp src/posix.cpp src/messagequeue.hpp)
target_link_libraries(link PUBLIC ${PCAP_LIBRARY} PRIVATE Threads::Threads)
set(LIBS_LINK "-Wl,--wrap=socket,--wrap=bind,--wrap=listen,--wrap=connect,--wrap=accept,--wrap=read,--wrap=write,--wrap=close,--wrap=getaddrinfo,--wrap=freeaddrinfo,--wrap=send,--wrap=sendto,--wrap=recv,--wrap=recvfrom,--wrap=setsockopt,--wrap=getsockname" link)


add_executable(tcptest_client test/tcpEchoClient.cpp)
add_executable(tcptest_server test/tcpEchoServer.cpp)
add_executable(ipRouter test/ipRouter.cpp)
target_link_libraries(tcptest_client ${LIBS_LINK})
target_link_libraries(tcptest_server ${LIBS_LINK})
target_link_libraries(ipRouter ${LIBS_LINK})