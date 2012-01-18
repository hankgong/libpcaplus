cmake_minimum_required(VERSION 2.8)

project(libpcaplus)

add_executable(pcap01 pcap01.cxx)
add_executable(pcap02 pcap02.cxx)
add_executable(pcap03 pcap03.cxx)
add_executable(pcap04 pcap04.cxx)


target_link_libraries(pcap01 pcap pthread)
target_link_libraries(pcap02 pcap)
target_link_libraries(pcap03 pcap)
target_link_libraries(pcap04 pcap)

