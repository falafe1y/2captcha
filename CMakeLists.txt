cmake_minimum_required(VERSION 3.10)

project(2Captcha)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(CURL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

add_executable(server server.cpp)
target_link_libraries(server PRIVATE CURL::libcurl Boost::system pthread)

add_executable(client client.cpp)
target_link_libraries(client PRIVATE Boost::system pthread)
